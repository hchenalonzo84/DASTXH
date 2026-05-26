"""
xss_display.py
- Construcción de filas XSS para la pestaña Resumen.

Responsabilidad:
- Filtrar grupos/hallazgos XSS sin señal útil.
- Decidir si la vista es agrupada o individual.
- Mostrar interpretación IA cuando exista en xss_ai_groups.
- Crear placeholder cuando Dalfox generó algo no mostrable.
- Calcular xss_display_count.

Nota importante:
- Si existen filas en xss_ai_groups, se usan como fuente principal
  porque allí vive la interpretación IA.
- Si no existen grupos IA útiles, se usa xss_findings como fallback.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from repositories.detail_helpers.detail_text import (
    as_list,
    clean_display_text,
    first_non_empty_text,
    is_empty_visual_value,
)


def has_valid_xss_group_signal(group: Dict[str, Any]) -> bool:
    """
    Determina si un grupo/fila IA XSS tiene suficiente señal para mostrarse.
    """
    severity = clean_display_text(group.get("severity_mode")).lower()
    signature = clean_display_text(group.get("payload_signature")).lower()
    parameter = clean_display_text(group.get("parameter_probable")).lower()
    sample_payloads = as_list(group.get("sample_payloads"))
    sample_evidence = as_list(group.get("sample_evidence"))

    has_payload = any(not is_empty_visual_value(item) for item in sample_payloads)
    has_evidence = any(not is_empty_visual_value(item) for item in sample_evidence)

    severity_unknown = severity in ("", "-", "unknown", "desconocido")
    signature_unknown = signature in ("", "-", "unknown", "payload_desconocido")
    parameter_unknown = parameter in ("", "-", "unknown", "desconocido")

    if severity_unknown and signature_unknown and parameter_unknown and not has_payload and not has_evidence:
        return False

    return has_payload or has_evidence


def has_valid_xss_finding_signal(finding: Dict[str, Any]) -> bool:
    """
    Determina si un hallazgo individual tiene suficiente señal para mostrarse.
    """
    payload = finding.get("payload")
    evidence = finding.get("evidence")
    severity = finding.get("severity")
    parameter = finding.get("param_name")

    has_payload = not is_empty_visual_value(payload)
    has_evidence = not is_empty_visual_value(evidence)
    severity_unknown = clean_display_text(severity).lower() in ("", "-", "unknown", "desconocido")
    parameter_unknown = clean_display_text(parameter).lower() in ("", "-", "unknown", "desconocido")

    if not has_payload and not has_evidence and severity_unknown and parameter_unknown:
        return False

    return has_payload or has_evidence


def build_no_valid_xss_row(raw_count: int = 0) -> Dict[str, Any]:
    """
    Construye una fila informativa cuando no hay hallazgos XSS válidos.
    """
    return {
        "row_order": "-",
        "parameter": "-",
        "payload": "-",
        "evidence": "Dalfox no devolvió payload/evidencia estructurada suficiente para mostrar un hallazgo XSS válido.",
        "severity": "Unknown",
        "occurrences": raw_count if raw_count > 0 else 1,
        "interpretation_humana": None,
        "risk_summary": None,
        "likely_root_cause": None,
        "recommended_review_area": None,
        "confidence": None,
        "model_name": None,
        "is_placeholder": True,
    }


def _build_row_from_ai_group(group: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye una fila visual usando xss_ai_groups.

    Esta es la fuente preferida porque contiene interpretación IA,
    risk_summary, likely_root_cause y recommended_review_area.
    """
    sample_payloads = group.get("sample_payloads") or []
    sample_evidence = group.get("sample_evidence") or []

    payload_example = first_non_empty_text(sample_payloads)
    evidence_example = first_non_empty_text(sample_evidence)

    return {
        "row_order": group.get("group_order"),
        "parameter": group.get("parameter_probable") or "-",
        "payload": payload_example or "-",
        "evidence": evidence_example or "-",
        "severity": group.get("severity_mode") or "-",
        "occurrences": group.get("occurrences") or 1,
        "interpretation_humana": group.get("interpretation_humana"),
        "risk_summary": group.get("risk_summary"),
        "likely_root_cause": group.get("likely_root_cause"),
        "recommended_review_area": group.get("recommended_review_area"),
        "confidence": group.get("confidence"),
        "model_name": group.get("model_name"),
        "is_placeholder": False,
    }


def _build_row_from_xss_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye una fila visual usando xss_findings como fallback.

    Esta fuente normalmente no trae interpretación IA.
    """
    return {
        "row_order": finding.get("finding_order"),
        "parameter": finding.get("param_name") or "-",
        "payload": finding.get("payload") or "-",
        "evidence": finding.get("evidence") or "-",
        "severity": finding.get("severity") or "-",
        "occurrences": 1,
        "interpretation_humana": finding.get("interpretation_humana"),
        "risk_summary": finding.get("risk_summary"),
        "likely_root_cause": finding.get("likely_root_cause"),
        "recommended_review_area": finding.get("recommended_review_area"),
        "confidence": finding.get("confidence"),
        "model_name": finding.get("model_name"),
        "is_placeholder": False,
    }


def build_xss_display_rows(
    xss_ai_groups_rows: List[Dict[str, Any]],
    enriched_xss_findings_rows: List[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]], int]:
    """
    Construye las filas visuales XSS para la pestaña Resumen.

    Regla corregida:
    - Si existen filas útiles en xss_ai_groups, se muestran esas filas,
      aunque sean entry_type='individual', porque ahí está la interpretación IA.
    - Si no existen filas IA útiles, se usa xss_findings como fallback.

    Retorna:
    - xss_display_mode: grouped o individual
    - xss_display_rows: filas para tabla
    - xss_display_count: filas reales sin placeholder
    """
    valid_xss_ai_groups_rows = [
        item for item in xss_ai_groups_rows
        if has_valid_xss_group_signal(item)
    ]

    valid_enriched_xss_findings_rows = [
        item for item in enriched_xss_findings_rows
        if has_valid_xss_finding_signal(item)
    ]

    has_real_groups = any(
        str(item.get("entry_type") or "").strip().lower() == "group"
        for item in valid_xss_ai_groups_rows
    )

    xss_display_mode = "grouped" if has_real_groups else "individual"
    xss_display_rows: List[Dict[str, Any]] = []

    # Fuente principal: xss_ai_groups, porque aquí vive la interpretación IA.
    if valid_xss_ai_groups_rows:
        for group in valid_xss_ai_groups_rows:
            xss_display_rows.append(_build_row_from_ai_group(group))

    # Fallback: xss_findings cuando no hay filas IA útiles.
    elif valid_enriched_xss_findings_rows:
        for finding in valid_enriched_xss_findings_rows:
            xss_display_rows.append(_build_row_from_xss_finding(finding))

    # Placeholder si hay datos crudos pero ninguno es visualmente válido.
    if not xss_display_rows and (xss_ai_groups_rows or enriched_xss_findings_rows):
        xss_display_rows.append(
            build_no_valid_xss_row(
                raw_count=len(xss_ai_groups_rows) or len(enriched_xss_findings_rows)
            )
        )

    xss_display_count = len(
        [item for item in xss_display_rows if not bool(item.get("is_placeholder"))]
    )

    return xss_display_mode, xss_display_rows, xss_display_count