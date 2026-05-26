"""
detail_queries.py
- Consultas SQL para construir el detalle enriquecido de una ejecución.

Responsabilidad:
- Cargar todos los bloques de datos necesarios para /executions/{id}.
- Mantener el SQL fuera de execution_detail_repository.py.
- Devolver datos crudos en diccionarios/listas para que el repositorio principal
  arme el ViewModel final.

Nota:
- Este archivo no transforma visualmente la data.
- Este archivo no compara curl vs hsecscan.
- Este archivo no construye xss_display_rows.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from repositories.db_connection import connect


def _fetch_all_as_dicts(cur) -> List[Dict[str, Any]]:
    """
    Convierte el resultado de fetchall en lista de diccionarios.
    """
    return [dict(row) for row in cur.fetchall()]


def load_execution_base(cur, execution_id: int) -> Optional[Dict[str, Any]]:
    """
    Carga datos base de ejecución y resultados principales.
    """
    cur.execute(
        """
        SELECT
            e.id,
            e.target_url,
            e.started_at,
            e.finished_at,
            e.status,
            e.error_message,
            e.request_source,
            e.scan_profile,
            e.enable_hsecscan,
            e.urls_ingresadas,
            e.urls_evaluadas,
            e.report_dir,
            hr.headers_evaluadas,
            hr.headers_presentes,
            hr.cumplimiento_pct,
            hr.http_score,
            hr.http_grade,
            hs.tool_rc AS hsecscan_rc,
            hs.raw_output AS hsecscan_raw_output,
            hs.structured_json AS hsecscan_structured_json,
            hs.summary_json AS hsecscan_summary_json,
            xr.tool_rc AS dalfox_rc,
            xr.findings_count,
            xr.summary_json,
            xr.raw_output AS dalfox_raw_output
        FROM executions e
        LEFT JOIN header_results hr
            ON hr.execution_id = e.id
        LEFT JOIN hsecscan_results hs
            ON hs.execution_id = e.id
        LEFT JOIN xss_results xr
            ON xr.execution_id = e.id
        WHERE e.id = %s;
        """,
        (execution_id,),
    )

    row = cur.fetchone()
    return dict(row) if row else None


def load_header_checks(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga cabeceras normalizadas de header_checks.
    """
    cur.execute(
        """
        SELECT
            id,
            execution_id,
            header_name,
            is_present,
            header_value,
            created_at
        FROM header_checks
        WHERE execution_id = %s
        ORDER BY id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_cookie_checks(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga cookies normalizadas de cookie_checks.
    """
    cur.execute(
        """
        SELECT
            id,
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
            interpreted_at,
            created_at
        FROM cookie_checks
        WHERE execution_id = %s
        ORDER BY id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_http_tests(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga pruebas HTTP detalladas.
    """
    cur.execute(
        """
        SELECT
            id,
            execution_id,
            test_id,
            name,
            category,
            status,
            score_delta,
            reason,
            recommendation,
            header_name,
            header_value,
            created_at
        FROM http_tests
        WHERE execution_id = %s
        ORDER BY id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_hsecscan_checks(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga checks hsecscan persistidos.
    """
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
            raw_check_json,
            created_at
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

    return _fetch_all_as_dicts(cur)


def load_xss_findings(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga hallazgos XSS individuales.
    """
    cur.execute(
        """
        SELECT
            id,
            execution_id,
            finding_order,
            source_type,
            target_url,
            param_name,
            payload,
            evidence,
            severity,
            raw_finding_json,
            created_at
        FROM xss_findings
        WHERE execution_id = %s
        ORDER BY finding_order ASC, id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_xss_ai_groups(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga grupos XSS interpretables por IA.
    """
    cur.execute(
        """
        SELECT
            id,
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
            sample_evidence,
            interpretation_humana,
            risk_summary,
            likely_root_cause,
            recommended_review_area,
            confidence,
            model_name,
            created_at
        FROM xss_ai_groups
        WHERE execution_id = %s
        ORDER BY group_order ASC, id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_artifacts(cur, execution_id: int) -> List[Dict[str, Any]]:
    """
    Carga artifacts generados por la ejecución.
    """
    cur.execute(
        """
        SELECT
            id,
            execution_id,
            artifact_type,
            file_name,
            relative_path,
            mime_type,
            size_bytes,
            created_at
        FROM artifacts
        WHERE execution_id = %s
        ORDER BY created_at ASC, id ASC;
        """,
        (execution_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_professional_report(cur, execution_id: int) -> Optional[Dict[str, Any]]:
    """
    Carga reporte general/profesional actual de la ejecución.
    """
    cur.execute(
        """
        SELECT
            id,
            execution_id,
            current_version_number,
            current_version_id,
            status,
            generated_by_ai,
            ai_model_name,
            report_title,
            executive_summary,
            scope_text,
            methodology_text,
            headers_analysis,
            hsecscan_analysis,
            cookies_analysis,
            xss_analysis,
            prioritized_findings,
            general_recommendations,
            limitations_text,
            conclusion_text,
            analyst_notes,
            created_at,
            updated_at
        FROM professional_reports
        WHERE execution_id = %s;
        """,
        (execution_id,),
    )

    row = cur.fetchone()
    return dict(row) if row else None


def load_professional_report_versions(
    cur,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Carga versiones históricas de un reporte general.
    """
    cur.execute(
        """
        SELECT
            id,
            professional_report_id,
            execution_id,
            version_number,
            version_label,
            change_type,
            change_reason,
            snapshot_json,
            content_hash,
            created_at,
            created_by
        FROM professional_report_versions
        WHERE professional_report_id = %s
        ORDER BY version_number DESC;
        """,
        (professional_report_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_professional_report_pdf_exports(
    cur,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Carga PDFs generados del reporte general.
    """
    cur.execute(
        """
        SELECT
            prpdf.id,
            prpdf.professional_report_id,
            prpdf.professional_report_version_id,
            prpdf.execution_id,
            prpdf.artifact_id,
            prpdf.pdf_file_name,
            prpdf.pdf_relative_path,
            prpdf.exported_at,
            prpdf.exported_by,
            prv.version_number,
            prv.version_label,
            a.file_name AS artifact_file_name,
            a.relative_path AS artifact_relative_path,
            a.mime_type AS artifact_mime_type,
            a.size_bytes AS artifact_size_bytes
        FROM professional_report_pdf_exports prpdf
        LEFT JOIN professional_report_versions prv
            ON prv.id = prpdf.professional_report_version_id
        LEFT JOIN artifacts a
            ON a.id = prpdf.artifact_id
        WHERE prpdf.professional_report_id = %s
        ORDER BY prpdf.exported_at DESC, prpdf.id DESC;
        """,
        (professional_report_id,),
    )

    return _fetch_all_as_dicts(cur)


def load_execution_detail_data(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Carga todos los datos crudos necesarios para construir el detalle.

    Retorna:
    - None si la ejecución no existe.
    - Diccionario con bloques crudos si existe.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            detail = load_execution_base(cur, execution_id)

            if not detail:
                conn.commit()
                return None

            header_rows = load_header_checks(cur, execution_id)
            cookie_rows_raw = load_cookie_checks(cur, execution_id)
            http_tests_rows = load_http_tests(cur, execution_id)
            hsecscan_checks_rows = load_hsecscan_checks(cur, execution_id)
            xss_findings_rows = load_xss_findings(cur, execution_id)
            xss_ai_groups_rows = load_xss_ai_groups(cur, execution_id)
            artifact_rows = load_artifacts(cur, execution_id)
            professional_report = load_professional_report(cur, execution_id)

            professional_report_versions: List[Dict[str, Any]] = []
            professional_report_pdf_exports: List[Dict[str, Any]] = []

            if professional_report:
                professional_report_id = int(professional_report["id"])
                professional_report_versions = load_professional_report_versions(
                    cur,
                    professional_report_id,
                )
                professional_report_pdf_exports = load_professional_report_pdf_exports(
                    cur,
                    professional_report_id,
                )

        conn.commit()

    return {
        "detail": detail,
        "header_rows": header_rows,
        "cookie_rows_raw": cookie_rows_raw,
        "http_tests_rows": http_tests_rows,
        "hsecscan_checks_rows": hsecscan_checks_rows,
        "xss_findings_rows": xss_findings_rows,
        "xss_ai_groups_rows": xss_ai_groups_rows,
        "artifact_rows": artifact_rows,
        "professional_report": professional_report,
        "professional_report_versions": professional_report_versions,
        "professional_report_pdf_exports": professional_report_pdf_exports,
    }