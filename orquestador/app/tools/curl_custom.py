"""
curl_custom.py
- CAPA 1: curl custom
- Obtiene headers/cookies y calcula cumplimiento (%).
- Esta versión también prepara datos más estructurados para
  persistirlos en tablas normalizadas.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from config import REQUIRED_HEADERS, UA
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
        "-D", "-",          # headers a stdout
        "-o", "/dev/null",  # body descartado
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

    Casos:
    - lista -> se une con ' | '
    - string -> se devuelve tal cual
    - vacío / None -> None
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

    Ejemplo:
    sessionid=abc123; Path=/; HttpOnly
    -> sessionid
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

    Ejemplo:
    SameSite=Lax -> Lax
    """
    if not cookie_raw:
        return None

    match = re.search(r"(?i)\bsamesite\s*=\s*([^;\s]+)", cookie_raw)
    if not match:
        return None

    value = match.group(1).strip()
    return value or None


def evaluate_headers_and_cookies(raw_headers_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evalúa:
    - cabeceras presentes/faltantes según REQUIRED_HEADERS
    - detalle por cabecera para persistencia normalizada
    - flags de cookies: Secure/HttpOnly/SameSite
    - cumplimiento_pct
    """
    headers = raw_headers_json.get("headers", {}) or {}

    present: List[str] = []
    missing: List[str] = []
    header_details: List[Dict[str, Any]] = []

    # ------------------------------------------------------
    # Detalle por header requerido
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

    headers_evaluadas = len(REQUIRED_HEADERS)
    headers_presentes = len(present)
    cumplimiento = (headers_presentes / headers_evaluadas * 100.0) if headers_evaluadas else 0.0

    return {
        "headers_evaluadas": headers_evaluadas,
        "headers_presentes": headers_presentes,
        "cumplimiento_pct": round(cumplimiento, 2),
        "present": present,
        "missing": missing,
        "header_details": header_details,
        "cookies_flags": cookies_eval,
    }