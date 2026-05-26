"""
header_repository.py
- Repositorio de resultados HTTP principales.

Responsabilidad:
- Guardar resultado general de cabeceras.
- Guardar checks normalizados de cabeceras.
- Guardar cookies observadas iniciales.
- Guardar pruebas HTTP detalladas.

Nota:
- Se conserva el comportamiento original: insert_header_results
  guarda headers + cookies + http_tests en una misma operación.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from repositories.db_connection import connect


def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a JSON string para columnas json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _normalize_risk_level(value: Any) -> Optional[str]:
    """
    Normaliza niveles de riesgo usados en cookies.
    """
    if value is None:
        return None

    text = str(value).strip().lower()

    if text in ("alta", "media", "baja", "informativa"):
        return text

    return None


def _build_header_details_if_missing(hdr_eval: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Reconstruye header_details si no viene en hdr_eval.

    Esto mantiene compatibilidad con resultados anteriores que
    solo traían listas present/missing.
    """
    header_details = hdr_eval.get("header_details")

    if isinstance(header_details, list):
        return header_details

    present = set(hdr_eval.get("present", []) or [])
    missing = set(hdr_eval.get("missing", []) or [])
    combined = list(present) + [header for header in missing if header not in present]

    result: List[Dict[str, Any]] = []

    for header_name in combined:
        result.append(
            {
                "header_name": str(header_name),
                "is_present": header_name in present,
                "header_value": None,
            }
        )

    return result


def _normalize_cookie_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza una cookie observada para guardar en cookie_checks.
    """
    cookie_raw = item.get("cookie_raw")

    if cookie_raw is None:
        cookie_raw = item.get("cookie", "")

    samesite_present = item.get("samesite_present")

    if samesite_present is None:
        samesite_present = bool(item.get("samesite"))

    return {
        "cookie_name": item.get("cookie_name"),
        "cookie_raw": str(cookie_raw or ""),
        "secure": bool(item.get("secure")),
        "httponly": bool(item.get("httponly")),
        "samesite_present": bool(samesite_present),
        "samesite_value": item.get("samesite_value"),
        "risk_level": _normalize_risk_level(item.get("risk_level")),
        "cwe_mappings": item.get("cwe_mappings"),
        "interpretation_humana": item.get("interpretation_humana"),
        "recommended_action": item.get("recommended_action"),
        "model_name": item.get("model_name"),
        "interpreted_at": item.get("interpreted_at"),
    }


def _normalize_http_test_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza una prueba HTTP antes de persistirla.
    """
    return {
        "test_id": str(item.get("test_id", "") or "").strip(),
        "name": str(item.get("name", "") or "").strip(),
        "category": str(item.get("category", "") or "").strip(),
        "status": str(item.get("status", "info") or "info").strip(),
        "score_delta": int(item.get("score_delta", 0) or 0),
        "reason": str(item.get("reason", "") or "").strip(),
        "recommendation": str(item.get("recommendation", "") or "").strip(),
        "header_name": item.get("header_name"),
        "header_value": item.get("header_value"),
    }


def _upsert_header_check(cur, execution_id: int, item: Dict[str, Any]) -> None:
    """
    Actualiza o inserta un header_check sin depender de ON CONFLICT.

    Esto evita fallos si el schema no tiene constraint único explícito.
    """
    header_name = str(item.get("header_name", ""))

    cur.execute(
        """
        UPDATE header_checks
        SET is_present = %s,
            header_value = %s
        WHERE execution_id = %s
          AND header_name = %s;
        """,
        (
            bool(item.get("is_present")),
            item.get("header_value"),
            execution_id,
            header_name,
        ),
    )

    if cur.rowcount == 0:
        cur.execute(
            """
            INSERT INTO header_checks (
                execution_id,
                header_name,
                is_present,
                header_value
            )
            VALUES (%s, %s, %s, %s);
            """,
            (
                execution_id,
                header_name,
                bool(item.get("is_present")),
                item.get("header_value"),
            ),
        )


def _upsert_http_test(cur, execution_id: int, item: Dict[str, Any]) -> None:
    """
    Actualiza o inserta un http_test sin depender de ON CONFLICT.
    """
    cur.execute(
        """
        UPDATE http_tests
        SET name = %s,
            category = %s,
            status = %s,
            score_delta = %s,
            reason = %s,
            recommendation = %s,
            header_name = %s,
            header_value = %s
        WHERE execution_id = %s
          AND test_id = %s;
        """,
        (
            item["name"],
            item["category"],
            item["status"],
            item["score_delta"],
            item["reason"],
            item["recommendation"],
            item["header_name"],
            item["header_value"],
            execution_id,
            item["test_id"],
        ),
    )

    if cur.rowcount == 0:
        cur.execute(
            """
            INSERT INTO http_tests (
                execution_id,
                test_id,
                name,
                category,
                status,
                score_delta,
                reason,
                recommendation,
                header_name,
                header_value
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (
                execution_id,
                item["test_id"],
                item["name"],
                item["category"],
                item["status"],
                item["score_delta"],
                item["reason"],
                item["recommendation"],
                item["header_name"],
                item["header_value"],
            ),
        )


def insert_header_results(
    dsn: str,
    execution_id: int,
    hdr_eval: Dict[str, Any],
    raw_headers_json: Dict[str, Any],
) -> None:
    """
    Inserta resultados HTTP normalizados.

    Guarda:
    - header_results
    - header_checks
    - cookie_checks
    - http_tests

    raw_headers_json se conserva como parámetro por compatibilidad
    con llamadas existentes.
    """
    _ = raw_headers_json

    header_details = _build_header_details_if_missing(hdr_eval)

    cookie_items = [
        _normalize_cookie_item(item)
        for item in (hdr_eval.get("cookies_flags", []) or [])
    ]

    http_tests = [
        _normalize_http_test_item(item)
        for item in (hdr_eval.get("http_tests", []) or [])
    ]

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO header_results (
                    execution_id,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    http_score,
                    http_grade
                )
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (
                    execution_id,
                    int(hdr_eval.get("headers_evaluadas", 0)),
                    int(hdr_eval.get("headers_presentes", 0)),
                    float(hdr_eval.get("cumplimiento_pct", 0)),
                    int(hdr_eval.get("http_score", 0)),
                    str(hdr_eval.get("http_grade", "F")),
                ),
            )

            for item in header_details:
                _upsert_header_check(cur, execution_id, item)

            for item in cookie_items:
                cur.execute(
                    """
                    INSERT INTO cookie_checks (
                        execution_id,
                        cookie_name,
                        cookie_raw,
                        secure,
                        httponly,
                        samesite_present,
                        samesite_value,
                        risk_level,
                        cwe_mappings,
                        interpretation_humana,
                        recommended_action,
                        model_name,
                        interpreted_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s::jsonb, %s, %s, %s, %s
                    );
                    """,
                    (
                        execution_id,
                        item.get("cookie_name"),
                        item.get("cookie_raw"),
                        item.get("secure"),
                        item.get("httponly"),
                        item.get("samesite_present"),
                        item.get("samesite_value"),
                        item.get("risk_level"),
                        _json_or_none(item.get("cwe_mappings")),
                        item.get("interpretation_humana"),
                        item.get("recommended_action"),
                        item.get("model_name"),
                        item.get("interpreted_at"),
                    ),
                )

            for item in http_tests:
                if (
                    not item["test_id"]
                    or not item["name"]
                    or not item["category"]
                    or not item["reason"]
                    or not item["recommendation"]
                ):
                    continue

                _upsert_http_test(cur, execution_id, item)

        conn.commit()