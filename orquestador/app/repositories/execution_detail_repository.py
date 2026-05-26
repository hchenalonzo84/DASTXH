"""
execution_detail_repository.py
- Repositorio de detalle enriquecido de ejecución DASTXH.

Responsabilidad:
- Construir el diccionario detail usado por la pantalla:
      /executions/{execution_id}

- Orquestar:
    * carga de datos crudos desde detail_queries.py
    * enriquecimiento de hsecscan
    * comparación curl vs hsecscan
    * construcción de filas visuales XSS
    * armado final del ViewModel para la GUI

Importante:
- Este archivo NO ejecuta herramientas externas.
- Este archivo NO llama IA.
- Este archivo debe mantenerse como orquestador, no como archivo gigante.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from repositories.detail_helpers.detail_queries import load_execution_detail_data
from repositories.detail_helpers.header_comparison import (
    build_header_layer_comparison,
    build_header_layer_comparison_summary,
)
from repositories.detail_helpers.hsecscan_classification import (
    enrich_hsecscan_check_rows,
    is_hsecscan_complementary,
    is_hsecscan_legacy,
    is_hsecscan_other_observation,
    is_hsecscan_primary,
)
from repositories.detail_helpers.xss_display import build_xss_display_rows


def _build_present_headers(header_rows: List[Dict[str, Any]]) -> List[str]:
    """
    Construye lista de cabeceras presentes a partir de header_checks.
    """
    return [
        row["header_name"]
        for row in header_rows
        if row.get("is_present")
    ]


def _build_missing_headers(header_rows: List[Dict[str, Any]]) -> List[str]:
    """
    Construye lista de cabeceras faltantes a partir de header_checks.
    """
    return [
        row["header_name"]
        for row in header_rows
        if not row.get("is_present")
    ]


def _build_raw_headers_derived(header_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Reconstruye una estructura raw_headers_json simple para compatibilidad visual.

    El template y algunos servicios esperan detail["raw_headers_json"].
    """
    return {
        "headers": {
            str(row["header_name"]).lower(): row.get("header_value")
            for row in header_rows
            if row.get("is_present")
        }
    }


def _build_cookies_flags_json(cookie_rows_raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Construye la lista detail["cookies_flags_json"] consumida por templates.

    Mantiene compatibilidad con nombres anteriores:
    - cookie
    - samesite
    y con nombres nuevos:
    - cookie_name
    - cookie_raw
    - samesite_present
    """
    cookies_flags_json: List[Dict[str, Any]] = []

    for row_item in cookie_rows_raw:
        cookies_flags_json.append(
            {
                "id": row_item.get("id"),
                "cookie": row_item.get("cookie_raw"),
                "secure": row_item.get("secure"),
                "httponly": row_item.get("httponly"),
                "samesite": row_item.get("samesite_present"),
                "cookie_name": row_item.get("cookie_name"),
                "cookie_raw": row_item.get("cookie_raw"),
                "samesite_present": row_item.get("samesite_present"),
                "samesite_value": row_item.get("samesite_value"),
                "risk_level": row_item.get("risk_level"),
                "cwe_mappings": row_item.get("cwe_mappings"),
                "interpretation_humana": row_item.get("interpretation_humana"),
                "recommended_action": row_item.get("recommended_action"),
                "model_name": row_item.get("model_name"),
                "interpreted_at": row_item.get("interpreted_at"),
            }
        )

    return cookies_flags_json


def _split_hsecscan_checks(
    hsecscan_checks_rows: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Divide checks hsecscan en grupos usados por GUI.
    """
    observed = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "observed"
    ]

    missing = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "missing"
    ]

    primary = [
        item for item in hsecscan_checks_rows
        if is_hsecscan_primary(item)
    ]

    complementary = [
        item for item in hsecscan_checks_rows
        if is_hsecscan_complementary(item)
    ]

    legacy = [
        item for item in hsecscan_checks_rows
        if is_hsecscan_legacy(item)
    ]

    other_observations = [
        item for item in hsecscan_checks_rows
        if is_hsecscan_other_observation(item)
    ]

    return {
        "observed": observed,
        "missing": missing,
        "primary": primary,
        "complementary": complementary,
        "legacy": legacy,
        "other_observations": other_observations,
    }


def _build_hsecscan_class_summary(
    hsecscan_groups: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, int]:
    """
    Construye resumen de clasificación hsecscan para tarjetas.
    """
    return {
        "primary": len(hsecscan_groups["primary"]),
        "complementary": len(hsecscan_groups["complementary"]),
        "legacy": len(hsecscan_groups["legacy"]),
        "other_observations": len(hsecscan_groups["other_observations"]),
    }


def get_execution_detail(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Devuelve el detalle enriquecido de una ejecución.

    Este es el ViewModel principal consumido por execution_detail.html.
    """
    loaded = load_execution_detail_data(dsn=dsn, execution_id=execution_id)

    if not loaded:
        return None

    detail = dict(loaded["detail"])
    header_rows = loaded["header_rows"]
    cookie_rows_raw = loaded["cookie_rows_raw"]
    http_tests_rows = loaded["http_tests_rows"]
    hsecscan_checks_rows = loaded["hsecscan_checks_rows"]
    xss_findings_rows = loaded["xss_findings_rows"]
    xss_ai_groups_rows = loaded["xss_ai_groups_rows"]
    artifact_rows = loaded["artifact_rows"]
    professional_report = loaded["professional_report"]
    professional_report_versions = loaded["professional_report_versions"]
    professional_report_pdf_exports = loaded["professional_report_pdf_exports"]

    # ======================================================
    # Cabeceras derivadas para compatibilidad con templates.
    # ======================================================
    present_headers = _build_present_headers(header_rows)
    missing_headers = _build_missing_headers(header_rows)
    raw_headers_derived = _build_raw_headers_derived(header_rows)

    # ======================================================
    # Cookies derivadas para vista Resumen/Detalle técnico.
    # ======================================================
    cookies_flags_json = _build_cookies_flags_json(cookie_rows_raw)

    # ======================================================
    # hsecscan enriquecido + grupos de clasificación.
    # ======================================================
    hsecscan_checks_rows = enrich_hsecscan_check_rows(hsecscan_checks_rows)
    hsecscan_groups = _split_hsecscan_checks(hsecscan_checks_rows)
    hsecscan_class_summary = _build_hsecscan_class_summary(hsecscan_groups)

    # ======================================================
    # Comparación curl vs hsecscan.
    # ======================================================
    header_layer_comparison = build_header_layer_comparison(
        http_tests_rows=http_tests_rows,
        hsecscan_checks_rows=hsecscan_checks_rows,
    )

    header_layer_comparison_summary = build_header_layer_comparison_summary(
        header_layer_comparison
    )

    # ======================================================
    # XSS display rows.
    # ======================================================
    # Por ahora se conserva la lista enriquecida igual a los hallazgos base.
    # Si más adelante se agregan interpretaciones por hallazgo individual,
    # este punto puede enriquecerse sin tocar las plantillas.
    enriched_xss_findings_rows = [dict(item) for item in xss_findings_rows]

    xss_display_mode, xss_display_rows, xss_display_count = build_xss_display_rows(
        xss_ai_groups_rows=xss_ai_groups_rows,
        enriched_xss_findings_rows=enriched_xss_findings_rows,
    )

    # ======================================================
    # Ensamble final del ViewModel.
    # ======================================================
    detail["present_json"] = present_headers
    detail["missing_json"] = missing_headers
    detail["raw_headers_json"] = raw_headers_derived
    detail["header_checks"] = header_rows
    detail["cookie_checks"] = cookie_rows_raw
    detail["cookies_flags_json"] = cookies_flags_json
    detail["http_tests"] = http_tests_rows

    detail["hsecscan_checks"] = hsecscan_checks_rows
    detail["hsecscan_observed_checks"] = hsecscan_groups["observed"]
    detail["hsecscan_missing_checks"] = hsecscan_groups["missing"]
    detail["hsecscan_primary_checks"] = hsecscan_groups["primary"]
    detail["hsecscan_complementary_checks"] = hsecscan_groups["complementary"]
    detail["hsecscan_legacy_checks"] = hsecscan_groups["legacy"]
    detail["hsecscan_other_observation_checks"] = hsecscan_groups["other_observations"]
    detail["hsecscan_class_summary"] = hsecscan_class_summary

    detail["header_layer_comparison"] = header_layer_comparison
    detail["header_layer_comparison_summary"] = header_layer_comparison_summary

    detail["xss_findings"] = enriched_xss_findings_rows
    detail["xss_ai_groups"] = xss_ai_groups_rows
    detail["xss_display_mode"] = xss_display_mode
    detail["xss_display_rows"] = xss_display_rows
    detail["xss_display_count"] = xss_display_count

    detail["artifacts"] = artifact_rows
    detail["professional_report"] = professional_report
    detail["professional_report_versions"] = professional_report_versions
    detail["professional_report_pdf_exports"] = professional_report_pdf_exports

    return detail