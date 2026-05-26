"""
professional_report_repository.py
- Repositorio del Reporte General Profesional de DASTXH.

Responsabilidad:
- Crear/consultar el reporte general editable.
- Guardar cambios del reporte general.
- Crear versiones históricas de solo lectura.
- Crear snapshots específicos para exportación PDF.
- Registrar exportaciones PDF.
- Listar versiones históricas y PDFs exportados.

Importante:
- Este archivo NO genera el contenido con IA.
- Este archivo NO genera el PDF.
- Este archivo solo persiste y consulta datos relacionados con el reporte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import config

from repositories.db_connection import connect
from utils import utc_now


# ==========================================================
# HELPERS PRIVADOS GENERALES
# ==========================================================

def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a texto JSON para columnas json/jsonb.

    Retorna None cuando el valor recibido es None.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


# ==========================================================
# HELPERS PRIVADOS: REPORTE GENERAL PROFESIONAL
# ==========================================================

def _professional_report_editable_fields() -> List[str]:
    """
    Devuelve la lista de campos editables del reporte general.

    Primero intenta leer PROFESSIONAL_REPORT_EDITABLE_FIELDS desde config.py.
    Si no existe o está vacío, usa una lista por defecto compatible
    con el esquema actual.
    """
    fields = getattr(config, "PROFESSIONAL_REPORT_EDITABLE_FIELDS", [])

    if isinstance(fields, list) and fields:
        return [str(item) for item in fields]

    return [
        "report_title",
        "executive_summary",
        "scope_text",
        "methodology_text",
        "headers_analysis",
        "hsecscan_analysis",
        "cookies_analysis",
        "xss_analysis",
        "prioritized_findings",
        "general_recommendations",
        "limitations_text",
        "conclusion_text",
        "analyst_notes",
    ]


def _empty_professional_report_payload() -> Dict[str, Any]:
    """
    Crea el payload base del reporte profesional.

    Todos los campos editables quedan como texto vacío, excepto
    report_title, que toma un título por defecto desde config.py.
    """
    payload = {field: "" for field in _professional_report_editable_fields()}

    payload["report_title"] = getattr(
        config,
        "PROFESSIONAL_REPORT_DEFAULT_TITLE",
        "Reporte general DASTXH",
    )

    return payload


def _normalize_professional_report_payload(
    payload: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Normaliza el contenido editable del reporte profesional.

    Garantiza:
    - que todos los campos existan;
    - que None se convierta en cadena vacía;
    - que report_title nunca quede vacío.
    """
    normalized = _empty_professional_report_payload()

    if not isinstance(payload, dict):
        return normalized

    for field in _professional_report_editable_fields():
        value = payload.get(field)

        if value is None:
            value = ""

        normalized[field] = str(value)

    if not normalized.get("report_title", "").strip():
        normalized["report_title"] = getattr(
            config,
            "PROFESSIONAL_REPORT_DEFAULT_TITLE",
            "Reporte general DASTXH",
        )

    return normalized


def _professional_report_snapshot_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye snapshot_json desde una fila de professional_reports.

    El snapshot representa una fotografía histórica del contenido editable.
    """
    payload: Dict[str, Any] = {}

    for field in _professional_report_editable_fields():
        payload[field] = row.get(field) or ""

    return _normalize_professional_report_payload(payload)


def _professional_report_content_hash(snapshot: Dict[str, Any]) -> str:
    """
    Calcula un hash estable del snapshot para trazabilidad.

    Se usa sort_keys=True para que el mismo contenido produzca el mismo hash
    sin depender del orden del diccionario.
    """
    raw = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _professional_report_version_label(version_number: int) -> str:
    """
    Construye la etiqueta amigable de una versión histórica.
    """
    prefix = getattr(config, "PROFESSIONAL_REPORT_VERSION_LABEL_PREFIX", "Versión")
    return f"{prefix} {version_number}"


def _next_professional_report_version_number(
    cur: Any,
    professional_report_id: int,
) -> int:
    """
    Calcula el siguiente número de versión para un reporte profesional.

    Esta función debe ejecutarse dentro de una transacción abierta.
    """
    cur.execute(
        """
        SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
        FROM professional_report_versions
        WHERE professional_report_id = %s;
        """,
        (professional_report_id,),
    )

    row = cur.fetchone()

    return int(row["next_version"] if row else 1)


def _insert_professional_report_version_cur(
    cur: Any,
    professional_report_id: int,
    execution_id: int,
    snapshot: Dict[str, Any],
    change_type: str,
    change_reason: Optional[str] = None,
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Inserta una versión histórica del reporte profesional.

    Importante:
    - Esta función NO abre conexión.
    - Esta función debe llamarse dentro de una transacción existente.
    """
    version_number = _next_professional_report_version_number(
        cur=cur,
        professional_report_id=professional_report_id,
    )

    content_hash = _professional_report_content_hash(snapshot)

    cur.execute(
        """
        INSERT INTO professional_report_versions (
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
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
        RETURNING
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
            created_by;
        """,
        (
            professional_report_id,
            execution_id,
            version_number,
            _professional_report_version_label(version_number),
            change_type,
            change_reason,
            _json_or_none(snapshot),
            content_hash,
            utc_now(),
            created_by,
        ),
    )

    row = cur.fetchone()

    if not row:
        raise RuntimeError("No fue posible crear la versión histórica del reporte general.")

    return dict(row)


# ==========================================================
# REPORTE GENERAL PROFESIONAL
# ==========================================================

def get_professional_report(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene el reporte general profesional actual editable.

    Retorna:
    - dict si existe;
    - None si la ejecución aún no tiene reporte general.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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

        conn.commit()

    return dict(row) if row else None


def get_or_create_professional_report(
    dsn: str,
    execution_id: int,
    initial_payload: Optional[Dict[str, Any]] = None,
    generated_by_ai: bool = False,
    ai_model_name: Optional[str] = None,
    change_type: str = "manual_save",
    change_reason: Optional[str] = None,
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Obtiene el reporte actual o crea uno nuevo.

    Si crea el reporte:
    - inserta professional_reports;
    - crea la primera versión histórica;
    - actualiza current_version_number y current_version_id.
    """
    existing = get_professional_report(dsn, execution_id)

    if existing:
        return existing

    payload = _normalize_professional_report_payload(initial_payload)
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO professional_reports (
                    execution_id,
                    current_version_number,
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
                )
                VALUES (
                    %s, 0, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                RETURNING
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
                    updated_at;
                """,
                (
                    execution_id,
                    getattr(config, "PROFESSIONAL_REPORT_STATUS_AI_GENERATED", "ai_generated")
                    if generated_by_ai
                    else getattr(config, "PROFESSIONAL_REPORT_STATUS_DRAFT", "draft"),
                    bool(generated_by_ai),
                    ai_model_name,
                    payload.get("report_title"),
                    payload.get("executive_summary"),
                    payload.get("scope_text"),
                    payload.get("methodology_text"),
                    payload.get("headers_analysis"),
                    payload.get("hsecscan_analysis"),
                    payload.get("cookies_analysis"),
                    payload.get("xss_analysis"),
                    payload.get("prioritized_findings"),
                    payload.get("general_recommendations"),
                    payload.get("limitations_text"),
                    payload.get("conclusion_text"),
                    payload.get("analyst_notes"),
                    now,
                    now,
                ),
            )

            inserted_report_row = cur.fetchone()

            if not inserted_report_row:
                raise RuntimeError("No fue posible crear el reporte general.")

            report = dict(inserted_report_row)

            version = _insert_professional_report_version_cur(
                cur=cur,
                professional_report_id=int(report["id"]),
                execution_id=execution_id,
                snapshot=_professional_report_snapshot_from_row(report),
                change_type=change_type,
                change_reason=change_reason,
                created_by=created_by,
            )

            cur.execute(
                """
                UPDATE professional_reports
                SET current_version_number = %s,
                    current_version_id = %s,
                    updated_at = %s
                WHERE id = %s
                RETURNING
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
                    updated_at;
                """,
                (
                    version["version_number"],
                    version["id"],
                    utc_now(),
                    report["id"],
                ),
            )

            updated_row = cur.fetchone()

            if not updated_row:
                raise RuntimeError("No fue posible actualizar la versión actual del reporte.")

            updated = dict(updated_row)

        conn.commit()

    return updated


def save_professional_report(
    dsn: str,
    execution_id: int,
    payload: Dict[str, Any],
    generated_by_ai: bool = False,
    ai_model_name: Optional[str] = None,
    change_type: str = "manual_save",
    change_reason: Optional[str] = None,
    updated_by: str = "web",
) -> Dict[str, Any]:
    """
    Guarda el reporte general editable y crea una nueva versión histórica.

    Si el reporte no existe, lo crea automáticamente.
    """
    normalized = _normalize_professional_report_payload(payload)
    existing = get_professional_report(dsn, execution_id)

    if not existing:
        return get_or_create_professional_report(
            dsn=dsn,
            execution_id=execution_id,
            initial_payload=normalized,
            generated_by_ai=generated_by_ai,
            ai_model_name=ai_model_name,
            change_type=change_type,
            change_reason=change_reason,
            created_by=updated_by,
        )

    report_id = int(existing["id"])
    now = utc_now()

    status = (
        getattr(config, "PROFESSIONAL_REPORT_STATUS_AI_GENERATED", "ai_generated")
        if generated_by_ai
        else getattr(config, "PROFESSIONAL_REPORT_STATUS_EDITED", "edited")
    )

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE professional_reports
                SET status = %s,
                    generated_by_ai = CASE WHEN %s THEN TRUE ELSE generated_by_ai END,
                    ai_model_name = COALESCE(%s, ai_model_name),
                    report_title = %s,
                    executive_summary = %s,
                    scope_text = %s,
                    methodology_text = %s,
                    headers_analysis = %s,
                    hsecscan_analysis = %s,
                    cookies_analysis = %s,
                    xss_analysis = %s,
                    prioritized_findings = %s,
                    general_recommendations = %s,
                    limitations_text = %s,
                    conclusion_text = %s,
                    analyst_notes = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s
                RETURNING
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
                    updated_at;
                """,
                (
                    status,
                    bool(generated_by_ai),
                    ai_model_name,
                    normalized.get("report_title"),
                    normalized.get("executive_summary"),
                    normalized.get("scope_text"),
                    normalized.get("methodology_text"),
                    normalized.get("headers_analysis"),
                    normalized.get("hsecscan_analysis"),
                    normalized.get("cookies_analysis"),
                    normalized.get("xss_analysis"),
                    normalized.get("prioritized_findings"),
                    normalized.get("general_recommendations"),
                    normalized.get("limitations_text"),
                    normalized.get("conclusion_text"),
                    normalized.get("analyst_notes"),
                    now,
                    report_id,
                    execution_id,
                ),
            )

            updated_report_row = cur.fetchone()

            if not updated_report_row:
                raise RuntimeError("No fue posible guardar el reporte general.")

            updated_report = dict(updated_report_row)

            version = _insert_professional_report_version_cur(
                cur=cur,
                professional_report_id=report_id,
                execution_id=execution_id,
                snapshot=_professional_report_snapshot_from_row(updated_report),
                change_type=change_type,
                change_reason=change_reason,
                created_by=updated_by,
            )

            cur.execute(
                """
                UPDATE professional_reports
                SET current_version_number = %s,
                    current_version_id = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s
                RETURNING
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
                    updated_at;
                """,
                (
                    version["version_number"],
                    version["id"],
                    utc_now(),
                    report_id,
                    execution_id,
                ),
            )

            final_report_row = cur.fetchone()

            if not final_report_row:
                raise RuntimeError("No fue posible actualizar la versión actual del reporte.")

            final_report = dict(final_report_row)

        conn.commit()

    final_report["created_version"] = version
    return final_report


def create_professional_report_pdf_snapshot_version(
    dsn: str,
    execution_id: int,
    payload: Dict[str, Any],
    change_reason: Optional[str] = "Snapshot usado para exportación PDF.",
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Crea una versión histórica específica para exportación PDF.

    Esta función guarda primero el contenido actual como snapshot
    y devuelve la versión creada.
    """
    report = save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=False,
        ai_model_name=None,
        change_type=getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_PDF_EXPORT_SNAPSHOT",
            "pdf_export_snapshot",
        ),
        change_reason=change_reason,
        updated_by=created_by,
    )

    version = report.get("created_version")

    if not isinstance(version, dict):
        raise RuntimeError("No fue posible crear la versión de snapshot para PDF.")

    return version


def list_professional_report_versions(
    dsn: str,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Lista versiones históricas de un reporte general.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]


def get_professional_report_version(
    dsn: str,
    version_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene una versión histórica específica por ID.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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
                WHERE id = %s;
                """,
                (version_id,),
            )
            row = cur.fetchone()

        conn.commit()

    return dict(row) if row else None


def register_professional_report_pdf_export(
    dsn: str,
    professional_report_id: int,
    professional_report_version_id: int,
    execution_id: int,
    artifact_id: Optional[int],
    pdf_file_name: str,
    pdf_relative_path: str,
    exported_by: str = "web",
) -> Dict[str, Any]:
    """
    Registra una exportación PDF del reporte general profesional.

    Además, actualiza el estado del reporte a pdf_exported.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO professional_report_pdf_exports (
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    exported_at,
                    exported_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING
                    id,
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    exported_at,
                    exported_by;
                """,
                (
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    utc_now(),
                    exported_by,
                ),
            )

            export_row_raw = cur.fetchone()

            if not export_row_raw:
                raise RuntimeError("No fue posible registrar la exportación PDF.")

            export_row = dict(export_row_raw)

            cur.execute(
                """
                UPDATE professional_reports
                SET status = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s;
                """,
                (
                    getattr(config, "PROFESSIONAL_REPORT_STATUS_PDF_EXPORTED", "pdf_exported"),
                    utc_now(),
                    professional_report_id,
                    execution_id,
                ),
            )

        conn.commit()

    return export_row


def list_professional_report_pdf_exports(
    dsn: str,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Lista exportaciones PDF de un reporte general.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]