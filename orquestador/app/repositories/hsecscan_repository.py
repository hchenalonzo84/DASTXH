"""
hsecscan_repository.py
- Repositorio de resultados hsecscan.

Responsabilidad:
- Guardar salida cruda y estructurada de hsecscan.
- Guardar checks normalizados de hsecscan.
- Listar checks para traducción asistida.
- Actualizar traducciones IA.

Este archivo no ejecuta hsecscan.
Solo persiste y consulta datos.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from repositories.db_connection import connect
from utils import utc_now


def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a JSON string para json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _normalize_risk_level(value: Any) -> Optional[str]:
    """
    Normaliza niveles de riesgo usados por hsecscan.
    """
    if value is None:
        return None

    text = str(value).strip().lower()

    if text in ("alta", "media", "baja", "informativa"):
        return text

    return None


def _unwrap_hsecscan_structured_payload(value: Any) -> Dict[str, Any]:
    """
    Acepta dos formas:
    - structured_json directo
    - wrapper con clave "structured"
    """
    if not isinstance(value, dict):
        return {}

    structured = value.get("structured")

    if isinstance(structured, dict):
        return structured

    return value


def _extract_hsecscan_summary(structured_json: Any) -> Optional[Dict[str, Any]]:
    """
    Extrae summary desde structured_json.
    """
    structured = _unwrap_hsecscan_structured_payload(structured_json)
    summary = structured.get("summary")

    if isinstance(summary, dict):
        return summary

    return None


def _extract_hsecscan_checks(structured_json: Any) -> List[Dict[str, Any]]:
    """
    Extrae observed_headers y missing_headers desde structured_json.
    """
    structured = _unwrap_hsecscan_structured_payload(structured_json)
    observed = structured.get("observed_headers") or []
    missing = structured.get("missing_headers") or []

    result: List[Dict[str, Any]] = []

    if isinstance(observed, list):
        result.extend([item for item in observed if isinstance(item, dict)])

    if isinstance(missing, list):
        result.extend([item for item in missing if isinstance(item, dict)])

    return result


def _normalize_hsecscan_check_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normaliza un registro hsecscan para hsecscan_checks.
    """
    header_name = str(item.get("header_name") or "").strip()

    if not header_name:
        return None

    record_type = str(item.get("record_type") or "").strip().lower()

    if record_type not in ("observed", "missing"):
        record_type = "missing" if item.get("value") is None else "observed"

    return {
        "record_type": record_type,
        "display_status": item.get("display_status"),
        "header_name": header_name,
        "header_value": item.get("value"),
        "risk_level": _normalize_risk_level(item.get("risk_level")),
        "reference_url": item.get("reference"),
        "security_description": item.get("security_description"),
        "security_reference": item.get("security_reference"),
        "recommendations": item.get("recommendations"),
        "cwe": item.get("cwe"),
        "cwe_url": item.get("cwe_url"),
        "https": item.get("https"),
        "security_description_es": item.get("security_description_es"),
        "recommendations_es": item.get("recommendations_es"),
        "cwe_es": item.get("cwe_es"),
        "translation_model_name": item.get("translation_model_name"),
        "translated_at": item.get("translated_at"),
        "raw_check_json": item,
    }


def _upsert_hsecscan_result(
    cur,
    execution_id: int,
    tool_rc: int,
    raw_output: str,
    structured_json: Optional[Dict[str, Any]],
    summary_json: Optional[Dict[str, Any]],
) -> None:
    """
    Actualiza o inserta hsecscan_results sin depender de ON CONFLICT.
    """
    cur.execute(
        """
        UPDATE hsecscan_results
        SET tool_rc = %s,
            raw_output = %s,
            structured_json = %s::jsonb,
            summary_json = %s::jsonb
        WHERE execution_id = %s;
        """,
        (
            int(tool_rc),
            raw_output,
            _json_or_none(structured_json),
            _json_or_none(summary_json),
            execution_id,
        ),
    )

    if cur.rowcount == 0:
        cur.execute(
            """
            INSERT INTO hsecscan_results (
                execution_id,
                tool_rc,
                raw_output,
                structured_json,
                summary_json
            )
            VALUES (%s, %s, %s, %s::jsonb, %s::jsonb);
            """,
            (
                execution_id,
                int(tool_rc),
                raw_output,
                _json_or_none(structured_json),
                _json_or_none(summary_json),
            ),
        )


def insert_hsecscan_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    raw_output: str,
    structured_json: Optional[Dict[str, Any]] = None,
    summary_json: Optional[Dict[str, Any]] = None,
    hsecscan_checks: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Inserta o actualiza resultados de hsecscan.

    Guarda:
    - hsecscan_results
    - hsecscan_checks
    """
    if summary_json is None and structured_json is not None:
        summary_json = _extract_hsecscan_summary(structured_json)

    if hsecscan_checks is None and structured_json is not None:
        hsecscan_checks = _extract_hsecscan_checks(structured_json)

    normalized_checks: List[Dict[str, Any]] = []

    for raw_item in hsecscan_checks or []:
        normalized = _normalize_hsecscan_check_item(raw_item)

        if normalized:
            normalized_checks.append(normalized)

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            _upsert_hsecscan_result(
                cur=cur,
                execution_id=execution_id,
                tool_rc=tool_rc,
                raw_output=raw_output,
                structured_json=structured_json,
                summary_json=summary_json,
            )

            cur.execute(
                """
                DELETE FROM hsecscan_checks
                WHERE execution_id = %s;
                """,
                (execution_id,),
            )

            for item in normalized_checks:
                cur.execute(
                    """
                    INSERT INTO hsecscan_checks (
                        execution_id,
                        record_type,
                        display_status,
                        header_name,
                        header_value,
                        risk_level,
                        reference_url,
                        security_description,
                        security_reference,
                        recommendations,
                        cwe,
                        cwe_url,
                        https,
                        security_description_es,
                        recommendations_es,
                        cwe_es,
                        translation_model_name,
                        translated_at,
                        raw_check_json
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb
                    );
                    """,
                    (
                        execution_id,
                        item["record_type"],
                        item["display_status"],
                        item["header_name"],
                        item["header_value"],
                        item["risk_level"],
                        item["reference_url"],
                        item["security_description"],
                        item["security_reference"],
                        item["recommendations"],
                        item["cwe"],
                        item["cwe_url"],
                        item["https"],
                        item.get("security_description_es"),
                        item.get("recommendations_es"),
                        item.get("cwe_es"),
                        item.get("translation_model_name"),
                        item.get("translated_at"),
                        _json_or_none(item["raw_check_json"]),
                    ),
                )

        conn.commit()


def list_hsecscan_checks_for_translation(
    dsn: str,
    execution_id: int,
) -> List[Dict[str, Any]]:
    """
    Devuelve checks hsecscan que pueden enviarse al servicio IA
    de traducción/asistencia lingüística.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    record_type,
                    display_status,
                    header_name,
                    header_value,
                    risk_level,
                    security_description,
                    recommendations,
                    cwe,
                    security_description_es,
                    recommendations_es,
                    cwe_es,
                    translation_model_name,
                    translated_at
                FROM hsecscan_checks
                WHERE execution_id = %s
                ORDER BY
                    CASE
                        WHEN risk_level = 'alta' THEN 1
                        WHEN risk_level = 'media' THEN 2
                        WHEN risk_level = 'baja' THEN 3
                        WHEN risk_level = 'informativa' THEN 4
                        ELSE 5
                    END,
                    record_type ASC,
                    header_name ASC,
                    id ASC;
                """,
                (execution_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]


def update_hsecscan_check_translations(
    dsn: str,
    execution_id: int,
    translations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza traducciones IA de hsecscan_checks.

    Cada elemento puede traer:
    - check_id o id
    - security_description_es
    - recommendations_es
    - cwe_es
    - translation_model_name
    - translated_at
    """
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in translations:
                raw_check_id = item.get("check_id", item.get("id"))

                try:
                    check_id = int(raw_check_id)
                except Exception:
                    continue

                if check_id <= 0:
                    continue

                cur.execute(
                    """
                    UPDATE hsecscan_checks
                    SET security_description_es = %s,
                        recommendations_es = %s,
                        cwe_es = %s,
                        translation_model_name = %s,
                        translated_at = %s
                    WHERE id = %s
                      AND execution_id = %s;
                    """,
                    (
                        item.get("security_description_es"),
                        item.get("recommendations_es"),
                        item.get("cwe_es"),
                        item.get("translation_model_name") or model_name,
                        item.get("translated_at") or now,
                        check_id,
                        execution_id,
                    ),
                )

        conn.commit()