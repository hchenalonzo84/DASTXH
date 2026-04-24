"""
curl_custom.py
- CAPA 1: curl custom
- Obtiene headers/cookies y calcula cumplimiento (%).
- Esta versión evoluciona la evaluación para soportar:
  * Grupo A: cabeceras principales
  * Grupo B: aislamiento / cross-origin
  * Grupo C: cookies
  * CORS básico como prueba separada
  * score y grade HTTP
- Mantiene compatibilidad con la estructura anterior:
  * present
  * missing
  * header_details
  * cookies_flags
  * cumplimiento_pct
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from config import (
    CORS_SCORE_WILDCARD,
    CORS_SCORE_WILDCARD_WITH_CREDENTIALS,
    CORS_TEST_ID,
    CORS_TEST_NAME,
    COOKIE_TESTS,
    GROUP_A_HEADERS,
    GROUP_A_RECOMMENDATIONS,
    GROUP_A_SCORES,
    GROUP_B_HEADERS,
    GROUP_B_RECOMMENDATIONS,
    GROUP_B_SCORES,
    REQUIRED_HEADERS,
    UA,
)
from utils import run_cmd


def curl_fetch_headers(url: str, timeout_s: int) -> Tuple[str, Dict[str, Any]]:
    """
    Ejecuta curl y devuelve:
    - raw_last_block: bloque final de headers (considerando redirects)
    - raw_headers_json: status_line + headers parseados + rc/stderr
    """
    cmd = [
        "curl",
        "-sS",
        "-L",
        "--max-time", str(timeout_s),
        "-A", UA,
        "-D", "-",
        "-o", "/dev/null",
        url,
    ]
    r = run_cmd(cmd)

    raw = r.out
    blocks = [b for b in re.split(r"\r?\n\r?\n", raw) if b.strip()]

    last = ""
    for b in reversed(blocks):
        if b.strip().startswith("HTTP/"):
            last = b
            break
    if not last:
        last = blocks[-1] if blocks else ""

    headers: Dict[str, Any] = {}
    lines = [ln.strip("\r") for ln in last.splitlines()]
    status_line = lines[0] if lines else ""

    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        lk = k.strip().lower()
        vv = v.strip()

        if lk in headers:
            if isinstance(headers[lk], list):
                headers[lk].append(vv)
            else:
                headers[lk] = [headers[lk], vv]
        else:
            headers[lk] = vv

    raw_headers_json = {
        "status_line": status_line,
        "headers": headers,
        "curl_rc": r.rc,
        "curl_stderr": (r.err or "")[-4000:],
    }

    return last, raw_headers_json


def _normalize_header_value(value: Any) -> str | None:
    """
    Convierte el valor de una cabecera a texto legible para almacenamiento.
    """
    if value is None:
        return None

    if isinstance(value, list):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return " | ".join(parts) if parts else None

    text = str(value).strip()
    return text if text else None


def _extract_cookie_name(cookie_raw: str) -> str | None:
    """
    Intenta extraer el nombre de la cookie desde la cadena Set-Cookie.
    """
    if not cookie_raw:
        return None

    first_part = cookie_raw.split(";", 1)[0].strip()
    if "=" not in first_part:
        return None

    name = first_part.split("=", 1)[0].strip()
    return name or None


def _extract_samesite_value(cookie_raw: str) -> str | None:
    """
    Intenta extraer el valor de SameSite desde la cookie raw.
    """
    if not cookie_raw:
        return None

    match = re.search(r"(?i)\bsamesite\s*=\s*([^;\s]+)", cookie_raw)
    if not match:
        return None

    value = match.group(1).strip()
    return value or None


def _build_http_test(
    test_id: str,
    name: str,
    category: str,
    status: str,
    score_delta: int,
    reason: str,
    recommendation: str,
    header_name: str | None = None,
    header_value: str | None = None,
) -> Dict[str, Any]:
    """
    Construye una prueba HTTP normalizada para score/reportes/UI.
    """
    return {
        "test_id": test_id,
        "name": name,
        "category": category,
        "status": status,  # passed / failed / warning / info
        "score_delta": int(score_delta),
        "reason": reason,
        "recommendation": recommendation,
        "header_name": header_name,
        "header_value": header_value,
    }


def _build_header_test(
    headers: Dict[str, Any],
    header_name: str,
    category: str,
    score_map: Dict[str, int],
    recommendation_map: Dict[str, str],
) -> Dict[str, Any]:
    """
    Evalúa una cabecera por presencia básica.
    """
    raw_value = headers.get(header_name.lower())
    normalized_value = _normalize_header_value(raw_value)
    is_present = header_name.lower() in headers

    if is_present:
        return _build_http_test(
            test_id=header_name.lower().replace("-", "_"),
            name=header_name,
            category=category,
            status="passed",
            score_delta=0,
            reason=f"La cabecera {header_name} está implementada.",
            recommendation="Ninguna.",
            header_name=header_name,
            header_value=normalized_value,
        )

    return _build_http_test(
        test_id=header_name.lower().replace("-", "_"),
        name=header_name,
        category=category,
        status="failed",
        score_delta=score_map.get(header_name, 0),
        reason=f"La cabecera {header_name} no está implementada.",
        recommendation=recommendation_map.get(header_name, "Implementar la cabecera recomendada."),
        header_name=header_name,
        header_value=normalized_value,
    )


def _evaluate_cors_basic(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evalúa CORS de manera básica y conservadora.

    Reglas:
    - sin Access-Control-Allow-Origin -> info, sin penalización
    - ACAO='*' y credenciales=true   -> failed
    - ACAO='*'                       -> warning
    - origen específico              -> passed
    """
    acao_raw = headers.get("access-control-allow-origin")
    acac_raw = headers.get("access-control-allow-credentials")

    acao = _normalize_header_value(acao_raw)
    acac = (_normalize_header_value(acac_raw) or "").strip().lower()

    if not acao:
        return _build_http_test(
            test_id=CORS_TEST_ID,
            name=CORS_TEST_NAME,
            category="grupo_b",
            status="info",
            score_delta=0,
            reason="No se expone una política CORS explícita en la respuesta.",
            recommendation="Ninguna.",
            header_name="Access-Control-Allow-Origin",
            header_value=None,
        )

    if acao == "*" and acac == "true":
        return _build_http_test(
            test_id=CORS_TEST_ID,
            name=CORS_TEST_NAME,
            category="grupo_b",
            status="failed",
            score_delta=CORS_SCORE_WILDCARD_WITH_CREDENTIALS,
            reason="La política CORS permite cualquier origen y además habilita credenciales.",
            recommendation="Restringir Access-Control-Allow-Origin y evitar combinar '*' con credenciales.",
            header_name="Access-Control-Allow-Origin",
            header_value=acao,
        )

    if acao == "*":
        return _build_http_test(
            test_id=CORS_TEST_ID,
            name=CORS_TEST_NAME,
            category="grupo_b",
            status="warning",
            score_delta=CORS_SCORE_WILDCARD,
            reason="La política CORS permite acceso desde cualquier origen.",
            recommendation="Restringir los orígenes permitidos si el recurso no requiere exposición pública amplia.",
            header_name="Access-Control-Allow-Origin",
            header_value=acao,
        )

    return _build_http_test(
        test_id=CORS_TEST_ID,
        name=CORS_TEST_NAME,
        category="grupo_b",
        status="passed",
        score_delta=0,
        reason="La respuesta expone una política CORS más restringida.",
        recommendation="Ninguna.",
        header_name="Access-Control-Allow-Origin",
        header_value=acao,
    )


def _evaluate_cookie_tests(cookies_eval: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Evalúa las cookies del Grupo C en forma agregada.

    Reglas:
    - si no hay cookies -> info, score 0
    - si existe al menos una cookie que incumple -> failed con score negativo
    - si todas cumplen -> passed
    """
    tests: List[Dict[str, Any]] = []

    if not cookies_eval:
        tests.append(
            _build_http_test(
                test_id="cookie_secure",
                name=COOKIE_TESTS["cookie_secure"]["name"],
                category="grupo_c",
                status="info",
                score_delta=0,
                reason="No se detectaron cookies en la respuesta final.",
                recommendation="Ninguna.",
            )
        )
        tests.append(
            _build_http_test(
                test_id="cookie_httponly",
                name=COOKIE_TESTS["cookie_httponly"]["name"],
                category="grupo_c",
                status="info",
                score_delta=0,
                reason="No se detectaron cookies en la respuesta final.",
                recommendation="Ninguna.",
            )
        )
        tests.append(
            _build_http_test(
                test_id="cookie_samesite",
                name=COOKIE_TESTS["cookie_samesite"]["name"],
                category="grupo_c",
                status="info",
                score_delta=0,
                reason="No se detectaron cookies en la respuesta final.",
                recommendation="Ninguna.",
            )
        )
        return tests

    any_insecure = any(not item.get("secure") for item in cookies_eval)
    any_not_httponly = any(not item.get("httponly") for item in cookies_eval)
    any_without_samesite = any(not item.get("samesite_present") for item in cookies_eval)

    tests.append(
        _build_http_test(
            test_id="cookie_secure",
            name=COOKIE_TESTS["cookie_secure"]["name"],
            category="grupo_c",
            status="failed" if any_insecure else "passed",
            score_delta=COOKIE_TESTS["cookie_secure"]["score"] if any_insecure else 0,
            reason=(
                "Se detectaron cookies sin el atributo Secure."
                if any_insecure
                else "Todas las cookies detectadas incluyen el atributo Secure."
            ),
            recommendation=(
                COOKIE_TESTS["cookie_secure"]["recommendation"]
                if any_insecure
                else "Ninguna."
            ),
        )
    )

    tests.append(
        _build_http_test(
            test_id="cookie_httponly",
            name=COOKIE_TESTS["cookie_httponly"]["name"],
            category="grupo_c",
            status="failed" if any_not_httponly else "passed",
            score_delta=COOKIE_TESTS["cookie_httponly"]["score"] if any_not_httponly else 0,
            reason=(
                "Se detectaron cookies sin el atributo HttpOnly."
                if any_not_httponly
                else "Todas las cookies detectadas incluyen el atributo HttpOnly."
            ),
            recommendation=(
                COOKIE_TESTS["cookie_httponly"]["recommendation"]
                if any_not_httponly
                else "Ninguna."
            ),
        )
    )

    tests.append(
        _build_http_test(
            test_id="cookie_samesite",
            name=COOKIE_TESTS["cookie_samesite"]["name"],
            category="grupo_c",
            status="failed" if any_without_samesite else "passed",
            score_delta=COOKIE_TESTS["cookie_samesite"]["score"] if any_without_samesite else 0,
            reason=(
                "Se detectaron cookies sin el atributo SameSite."
                if any_without_samesite
                else "Todas las cookies detectadas incluyen el atributo SameSite."
            ),
            recommendation=(
                COOKIE_TESTS["cookie_samesite"]["recommendation"]
                if any_without_samesite
                else "Ninguna."
            ),
        )
    )

    return tests


def _calculate_http_score(http_tests: List[Dict[str, Any]]) -> int:
    """
    Calcula el score HTTP partiendo de 100 y aplicando penalizaciones.
    """
    score = 100
    for test in http_tests:
        score += int(test.get("score_delta", 0))

    if score < 0:
        return 0
    if score > 100:
        return 100
    return score


def _calculate_http_grade(score: int) -> str:
    """
    Devuelve una nota simple basada en el score.
    """
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def evaluate_headers_and_cookies(raw_headers_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evalúa:
    - cabeceras presentes/faltantes según REQUIRED_HEADERS
    - detalle por cabecera para persistencia normalizada
    - flags de cookies: Secure/HttpOnly/SameSite
    - cumplimiento_pct
    - score HTTP, grade y pruebas detalladas
    """
    headers = raw_headers_json.get("headers", {}) or {}

    present: List[str] = []
    missing: List[str] = []
    header_details: List[Dict[str, Any]] = []

    # ------------------------------------------------------
    # Compatibilidad: detalle por cabecera requerida
    # ------------------------------------------------------
    for h in REQUIRED_HEADERS:
        raw_value = headers.get(h.lower())
        is_present = h.lower() in headers
        normalized_value = _normalize_header_value(raw_value)

        if is_present:
            present.append(h)
        else:
            missing.append(h)

        header_details.append(
            {
                "header_name": h,
                "is_present": is_present,
                "header_value": normalized_value,
            }
        )

    # ------------------------------------------------------
    # Evaluación de cookies
    # ------------------------------------------------------
    sc = headers.get("set-cookie")
    cookies = sc if isinstance(sc, list) else ([sc] if sc else [])

    cookies_eval: List[Dict[str, Any]] = []
    for cookie_raw in cookies:
        cookie_text = str(cookie_raw)
        cookie_lower = cookie_text.lower()
        samesite_value = _extract_samesite_value(cookie_text)

        cookies_eval.append(
            {
                "cookie_name": _extract_cookie_name(cookie_text),
                "cookie_raw": cookie_text,
                "secure": "secure" in cookie_lower,
                "httponly": "httponly" in cookie_lower,
                "samesite_present": samesite_value is not None,
                "samesite_value": samesite_value,
            }
        )

    # ------------------------------------------------------
    # Grupo A
    # ------------------------------------------------------
    http_tests: List[Dict[str, Any]] = []
    for header_name in GROUP_A_HEADERS:
        http_tests.append(
            _build_header_test(
                headers=headers,
                header_name=header_name,
                category="grupo_a",
                score_map=GROUP_A_SCORES,
                recommendation_map=GROUP_A_RECOMMENDATIONS,
            )
        )

    # ------------------------------------------------------
    # Grupo B (cabeceras)
    # ------------------------------------------------------
    for header_name in GROUP_B_HEADERS:
        http_tests.append(
            _build_header_test(
                headers=headers,
                header_name=header_name,
                category="grupo_b",
                score_map=GROUP_B_SCORES,
                recommendation_map=GROUP_B_RECOMMENDATIONS,
            )
        )

    # ------------------------------------------------------
    # Grupo B (CORS básico)
    # ------------------------------------------------------
    http_tests.append(_evaluate_cors_basic(headers))

    # ------------------------------------------------------
    # Grupo C (cookies)
    # ------------------------------------------------------
    http_tests.extend(_evaluate_cookie_tests(cookies_eval))

    # ------------------------------------------------------
    # Compatibilidad con el resumen anterior
    # ------------------------------------------------------
    headers_evaluadas = len(REQUIRED_HEADERS)
    headers_presentes = len(present)
    cumplimiento = (headers_presentes / headers_evaluadas * 100.0) if headers_evaluadas else 0.0

    # ------------------------------------------------------
    # Score general HTTP
    # ------------------------------------------------------
    http_score = _calculate_http_score(http_tests)
    http_grade = _calculate_http_grade(http_score)

    return {
        "headers_evaluadas": headers_evaluadas,
        "headers_presentes": headers_presentes,
        "cumplimiento_pct": round(cumplimiento, 2),
        "present": present,
        "missing": missing,
        "header_details": header_details,
        "cookies_flags": cookies_eval,

        # Nuevo modelo enriquecido
        "http_score": http_score,
        "http_grade": http_grade,
        "http_tests": http_tests,
    }