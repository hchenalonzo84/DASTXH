"""
xss_repository.py
- Repositorio de resultados Dalfox / XSS.

Responsabilidad:
- Guardar resultado general de Dalfox.
- Guardar hallazgos XSS normalizados.
- Guardar grupos XSS para interpretación IA.
- Actualizar interpretaciones IA de grupos XSS.

Este archivo no ejecuta Dalfox.
Solo persiste y consulta datos.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from repositories.db_connection import connect


def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a JSON string para json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _normalize_xss_ai_group_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza una entrada agrupada XSS antes de persistirla.

    Soporta:
    - entry_type = individual
    - entry_type = group
    """
    entry_type = str(item.get("entry_type", "group") or "group").strip()
    finding_orders = item.get("finding_orders")

    if not isinstance(finding_orders, list):
        finding_orders = item.get("sample_finding_orders") or []

    sample_payloads = item.get("sample_payloads") or []
    sample_evidence = item.get("sample_evidence") or []

    if entry_type == "individual":
        finding_order = int(item.get("finding_order", 0) or 0)

        if not finding_orders and finding_order > 0:
            finding_orders = [finding_order]

        payload = item.get("payload")
        evidence = item.get("evidence")

        if not sample_payloads and payload:
            sample_payloads = [payload]

        if not sample_evidence and evidence:
            sample_evidence = [evidence]

        return {
            "entry_type": "individual",
            "parameter_probable": item.get("parameter_probable"),
            "context_probable": item.get("context_probable"),
            "severity_mode": item.get("severity") or item.get("severity_mode"),
            "payload_signature": item.get("payload_signature"),
            "occurrences": 1,
            "target_url": item.get("target_url"),
            "sample_finding_orders": finding_orders,
            "sample_payloads": sample_payloads,
            "sample_evidence": sample_evidence,
        }

    return {
        "entry_type": "group",
        "parameter_probable": item.get("parameter_probable"),
        "context_probable": item.get("context_probable"),
        "severity_mode": item.get("severity_mode"),
        "payload_signature": item.get("payload_signature"),
        "occurrences": int(item.get("occurrences", 1) or 1),
        "target_url": item.get("target_url"),
        "sample_finding_orders": finding_orders,
        "sample_payloads": sample_payloads,
        "sample_evidence": sample_evidence,
    }


def _upsert_xss_finding(cur, execution_id: int, item: Dict[str, Any]) -> None:
    """
    Actualiza o inserta un hallazgo XSS sin depender de ON CONFLICT.
    """
    finding_order = int(item.get("finding_order", 0))

    cur.execute(
        """
        UPDATE xss_findings
        SET source_type = %s,
            target_url = %s,
            param_name = %s,
            payload = %s,
            evidence = %s,
            severity = %s,
            raw_finding_json = %s::jsonb
        WHERE execution_id = %s
          AND finding_order = %s;
        """,
        (
            item.get("source_type"),
            item.get("target_url"),
            item.get("param_name"),
            item.get("payload"),
            item.get("evidence"),
            item.get("severity"),
            _json_or_none(item.get("raw_finding_json")),
            execution_id,
            finding_order,
        ),
    )

    if cur.rowcount == 0:
        cur.execute(
            """
            INSERT INTO xss_findings (
                execution_id,
                finding_order,
                source_type,
                target_url,
                param_name,
                payload,
                evidence,
                severity,
                raw_finding_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb);
            """,
            (
                execution_id,
                finding_order,
                item.get("source_type"),
                item.get("target_url"),
                item.get("param_name"),
                item.get("payload"),
                item.get("evidence"),
                item.get("severity"),
                _json_or_none(item.get("raw_finding_json")),
            ),
        )


def _upsert_xss_ai_group(
    cur,
    execution_id: int,
    group_order: int,
    item: Dict[str, Any],
) -> None:
    """
    Actualiza o inserta un grupo XSS IA sin depender de ON CONFLICT.
    """
    cur.execute(
        """
        UPDATE xss_ai_groups
        SET entry_type = %s,
            parameter_probable = %s,
            context_probable = %s,
            severity_mode = %s,
            payload_signature = %s,
            occurrences = %s,
            target_url = %s,
            sample_finding_orders = %s::jsonb,
            sample_payloads = %s::jsonb,
            sample_evidence = %s::jsonb
        WHERE execution_id = %s
          AND group_order = %s;
        """,
        (
            item["entry_type"],
            item["parameter_probable"],
            item["context_probable"],
            item["severity_mode"],
            item["payload_signature"],
            item["occurrences"],
            item["target_url"],
            _json_or_none(item["sample_finding_orders"]),
            _json_or_none(item["sample_payloads"]),
            _json_or_none(item["sample_evidence"]),
            execution_id,
            group_order,
        ),
    )

    if cur.rowcount == 0:
        cur.execute(
            """
            INSERT INTO xss_ai_groups (
                execution_id,
                group_order,
                entry_type,
                parameter_probable,
                context_probable,
                severity_mode,
                payload_signature,
                occurrences,
                target_url,
                sample_finding_orders,
                sample_payloads,
                sample_evidence
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb);
            """,
            (
                execution_id,
                group_order,
                item["entry_type"],
                item["parameter_probable"],
                item["context_probable"],
                item["severity_mode"],
                item["payload_signature"],
                item["occurrences"],
                item["target_url"],
                _json_or_none(item["sample_finding_orders"]),
                _json_or_none(item["sample_payloads"]),
                _json_or_none(item["sample_evidence"]),
            ),
        )


def insert_xss_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    findings_count: int,
    summary_json: Any,
    raw_output: str,
    xss_findings: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Inserta resultados XSS normalizados.

    Guarda:
    - xss_results
    - xss_findings
    """
    finding_rows = xss_findings or []

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO xss_results (
                    execution_id,
                    tool_rc,
                    findings_count,
                    summary_json,
                    raw_output
                )
                VALUES (%s, %s, %s, %s::jsonb, %s);
                """,
                (
                    execution_id,
                    int(tool_rc),
                    int(findings_count),
                    _json_or_none(summary_json),
                    raw_output,
                ),
            )

            for item in finding_rows:
                _upsert_xss_finding(cur, execution_id, item)

        conn.commit()


def insert_xss_ai_groups(
    dsn: str,
    execution_id: int,
    xss_ai_payload: Dict[str, Any],
) -> None:
    """
    Persiste agrupación XSS preparada para interpretación IA.

    Guarda:
    - xss_ai_groups
    """
    entries = xss_ai_payload.get("entries", []) or []

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for index, raw_item in enumerate(entries, start=1):
                item = _normalize_xss_ai_group_item(raw_item)
                _upsert_xss_ai_group(cur, execution_id, index, item)

        conn.commit()


def update_xss_ai_group_interpretations(
    dsn: str,
    execution_id: int,
    interpretations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza interpretaciones IA sobre grupos XSS.

    Cada elemento puede traer:
    - group_order
    - interpretation_humana
    - risk_summary
    - likely_root_cause
    - recommended_review_area
    - confidence
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in interpretations:
                group_order = int(item.get("group_order", 0) or 0)

                if group_order <= 0:
                    continue

                cur.execute(
                    """
                    UPDATE xss_ai_groups
                    SET interpretation_humana = %s,
                        risk_summary = %s,
                        likely_root_cause = %s,
                        recommended_review_area = %s,
                        confidence = %s,
                        model_name = %s
                    WHERE execution_id = %s
                      AND group_order = %s;
                    """,
                    (
                        item.get("interpretation_humana"),
                        item.get("risk_summary"),
                        item.get("likely_root_cause"),
                        item.get("recommended_review_area"),
                        item.get("confidence"),
                        model_name,
                        execution_id,
                        group_order,
                    ),
                )

        conn.commit()