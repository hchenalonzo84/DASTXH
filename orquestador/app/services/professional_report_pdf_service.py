"""
professional_report_pdf_service.py
- Servicio para generar el PDF del Reporte General de DASTXH.

Objetivo:
- Tomar una versión histórica exacta del reporte general.
- Generar un PDF a partir de esa versión.
- Incluir texto editable + evidencia objetiva resumida.
- Guardar el PDF en la carpeta de archivos técnicos de la ejecución:
    /work/reports/<run_id>/reporte_general_vX_YYYYMMDD_HHMMSS.pdf

Regla del reporte:
- El texto editable interpreta.
- Las tablas de evidencia respaldan objetivamente el análisis.
- La evidencia se toma de los mismos datos usados en la pestaña Resumen.

Regla de fechas:
- PostgreSQL puede conservar fechas en UTC.
- El PDF debe mostrar fechas en la zona horaria configurada en config.py.
- Para Guatemala se usa America/Guatemala.

Importante:
- Este archivo NO llama IA.
- Este archivo NO modifica la base de datos.
- Este archivo NO registra archivos técnicos en BD.
- Este archivo NO decide contenido técnico.
- Solo toma texto ya guardado/versionado y lo convierte a PDF.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

import config
from services.professional_report_service import build_professional_report_pdf_context


# ==========================================================
# HELPERS GENERALES
# ==========================================================

def _safe_text(value: Any, default: str = "") -> str:
    """
    Convierte cualquier valor a texto seguro.
    """
    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return text


def _get_display_timezone() -> ZoneInfo:
    """
    Devuelve la zona horaria configurada para mostrar fechas.

    Por defecto:
    - America/Guatemala
    """
    timezone_name = getattr(config, "DISPLAY_TIMEZONE", "America/Guatemala")

    try:
        return ZoneInfo(timezone_name)
    except Exception:
        return ZoneInfo("America/Guatemala")


def _get_display_datetime_format() -> str:
    """
    Devuelve el formato visible de fecha/hora.
    """
    return getattr(config, "DISPLAY_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")


def _parse_datetime_value(value: Any) -> Optional[datetime]:
    """
    Convierte un valor recibido desde BD o string a datetime.

    Casos soportados:
    - datetime con zona horaria.
    - datetime sin zona horaria.
    - string ISO con offset.
    - string ISO con Z.
    - string simple compatible con fromisoformat.

    Regla:
    - Si el datetime viene sin zona horaria, se asume UTC.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(text)
        except Exception:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _format_local_datetime(value: Any) -> str:
    """
    Formatea fechas para el PDF usando hora local de Guatemala.

    No modifica la fecha original guardada en BD.
    Solo cambia la presentación.
    """
    parsed = _parse_datetime_value(value)

    if parsed is None:
        return "-"

    local_dt = parsed.astimezone(_get_display_timezone())
    return local_dt.strftime(_get_display_datetime_format())


def _execution_status_label(value: Any) -> str:
    """
    Traduce estados internos de ejecución a español.
    """
    text = _safe_text(value, "-")
    labels = getattr(config, "EXECUTION_STATUS_LABELS", {})

    if isinstance(labels, dict):
        return labels.get(text, text)

    return text


def _report_change_type_label(value: Any) -> str:
    """
    Traduce tipos internos de cambio del reporte a español.

    Esta función se conserva por si se necesita en el futuro,
    aunque el PDF ya no muestra "Tipo de versión" en metadatos.
    """
    text = _safe_text(value, "-")
    labels = getattr(config, "PROFESSIONAL_REPORT_CHANGE_TYPE_LABELS", {})

    if isinstance(labels, dict):
        return labels.get(text, text)

    return text


def _sanitize_filename_part(value: Any, default: str = "reporte") -> str:
    """
    Limpia una parte de nombre de archivo para evitar caracteres problemáticos.
    """
    text = _safe_text(value, default).lower()

    replacements = {
        "á": "a",
        "é": "e",
        "í": "i",
        "ó": "o",
        "ú": "u",
        "ñ": "n",
        "ü": "u",
    }

    for source, target in replacements.items():
        text = text.replace(source, target)

    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")

    if not text:
        return default

    return text[:120]


def _ensure_directory(path: Path) -> None:
    """
    Crea una carpeta si no existe.
    """
    path.mkdir(parents=True, exist_ok=True)


def _get_run_folder_name(detail: Dict[str, Any]) -> str:
    """
    Obtiene el nombre de carpeta de la ejecución desde report_dir.

    Ejemplo:
    /work/reports/20260520_213452 -> 20260520_213452
    """
    report_dir = _safe_text(detail.get("report_dir"))

    if report_dir:
        folder_name = Path(report_dir).name

        if folder_name:
            return folder_name

    execution_id = detail.get("id") or "sin_id"
    return f"execution_{execution_id}"


def _resolve_output_directory(
    detail: Dict[str, Any],
    reports_root: Path,
) -> Path:
    """
    Resuelve la carpeta física donde se guardará el PDF.

    Regla:
    - Si detail.report_dir es absoluto, se usa esa ruta.
    - Si no, se usa reports_root / run_id.
    """
    report_dir = _safe_text(detail.get("report_dir"))

    if report_dir:
        candidate = Path(report_dir)

        if candidate.is_absolute():
            return candidate

    return reports_root / _get_run_folder_name(detail)


def _build_pdf_file_name(version_number: int) -> str:
    """
    Construye un nombre único para el PDF exportado.
    """
    prefix = getattr(
        config,
        "PROFESSIONAL_REPORT_FILE_PREFIX",
        "reporte_general",
    )

    safe_prefix = _sanitize_filename_part(prefix, "reporte_general")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    return f"{safe_prefix}_v{version_number}_{timestamp}.pdf"


def _build_relative_path(run_folder_name: str, file_name: str) -> str:
    """
    Construye una ruta relativa lógica para registrar como archivo técnico.
    """
    return f"reports/{run_folder_name}/{file_name}"
# ==========================================================
# HELPERS DE CONTENIDO
# ==========================================================

def _get_snapshot(version: Dict[str, Any]) -> Dict[str, Any]:
    """
    Obtiene el snapshot_json de una versión histórica.
    """
    snapshot = version.get("snapshot_json")

    if isinstance(snapshot, dict):
        return snapshot

    return {}


def _clean_report_text(value: Any) -> str:
    """
    Limpia texto para evitar caracteres problemáticos en PDF.

    No elimina tildes ni caracteres normales en español.
    """
    text = _safe_text(value)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)

    return text.strip()


def _truncate_text(value: Any, max_chars: int = 320) -> str:
    """
    Recorta texto largo para evitar que las tablas del PDF se vuelvan ilegibles.
    """
    text = _clean_report_text(value)

    if len(text) <= max_chars:
        return text

    return text[:max_chars].rstrip() + "..."


def _paragraph_chunks(text: str) -> List[str]:
    """
    Divide texto en bloques compatibles con Paragraph.

    - Respeta párrafos separados por líneas en blanco.
    - Mantiene listas simples línea por línea.
    """
    clean = _clean_report_text(text)

    if not clean:
        return ["-"]

    chunks: List[str] = []
    current: List[str] = []

    for line in clean.split("\n"):
        raw_line = line.strip()

        if not raw_line:
            if current:
                chunks.append("\n".join(current))
                current = []
            continue

        if raw_line.startswith("- ") or raw_line.startswith("* "):
            if current:
                chunks.append("\n".join(current))
                current = []

            chunks.append(raw_line)
            continue

        current.append(raw_line)

    if current:
        chunks.append("\n".join(current))

    return chunks


def _to_reportlab_html(text: str) -> str:
    """
    Convierte texto plano a contenido seguro para ReportLab Paragraph.
    """
    escaped = html.escape(text)
    escaped = escaped.replace("\n", "<br/>")
    return escaped


def _make_paragraph(text: str, style: Any) -> Any:
    """
    Crea un Paragraph seguro.
    """
    from reportlab.platypus import Paragraph

    return Paragraph(_to_reportlab_html(text), style)


def _cell(value: Any, style: Any, max_chars: int = 260) -> Any:
    """
    Convierte un valor de tabla a Paragraph seguro.
    """
    return _make_paragraph(_truncate_text(value, max_chars=max_chars), style)


def _build_header_footer(canvas: Any, doc: Any, detail: Dict[str, Any], version: Dict[str, Any]) -> None:
    """
    Dibuja encabezado y pie de página en cada página.
    """
    canvas.saveState()

    width, height = doc.pagesize

    execution_id = _safe_text(detail.get("id"), "-")
    version_label = _safe_text(version.get("version_label"), "-")

    header_text = f"DASTXH - Reporte general | Ejecución {execution_id} | {version_label}"
    footer_text = f"Página {doc.page}"

    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, height - 22, header_text)

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - doc.rightMargin, 18, footer_text)

    canvas.restoreState()


def _build_metadata_table(detail: Dict[str, Any], version: Dict[str, Any]) -> List[List[str]]:
    """
    Construye una tabla simple de metadatos del reporte.

    Cambios aplicados:
    - Estado se muestra en español.
    - Fechas se muestran en hora local de Guatemala.
    - Se quitó "Flujo aplicado".
    - Se quitó "Tipo de versión".
    """
    return [
        ["Ejecución", _safe_text(detail.get("id"), "-")],
        ["URL objetivo", _safe_text(detail.get("target_url"), "-")],
        ["Estado de ejecución", _execution_status_label(detail.get("status"))],
        ["Inicio", _format_local_datetime(detail.get("started_at"))],
        ["Fin", _format_local_datetime(detail.get("finished_at"))],
        ["Versión del reporte", _safe_text(version.get("version_label"), "-")],
        ["Fecha de versión", _format_local_datetime(version.get("created_at"))],
    ]


def _build_technical_summary_table(detail: Dict[str, Any]) -> List[List[str]]:
    """
    Construye una tabla resumen con indicadores técnicos principales.
    """
    cumplimiento = detail.get("cumplimiento_pct")

    if cumplimiento is None:
        cumplimiento_text = "-"
    else:
        cumplimiento_text = f"{cumplimiento}%"

    headers_evaluadas = _safe_text(detail.get("headers_evaluadas"), "-")
    headers_presentes = _safe_text(detail.get("headers_presentes"), "-")
    xss_count = _safe_text(detail.get("xss_display_count"), "0")

    hsecscan_rc = detail.get("hsecscan_rc")

    if hsecscan_rc is None:
        hsecscan_text = "-"
    else:
        hsecscan_text = str(hsecscan_rc)

    cookies_count = len(detail.get("cookies_flags_json") or [])
    technical_files_count = len(detail.get("artifacts") or [])

    technical_files_label = getattr(
        config,
        "TECHNICAL_FILES_LABEL",
        "Archivos técnicos registrados",
    )

    return [
        ["Cumplimiento de cabeceras", cumplimiento_text],
        ["Cabeceras evaluadas", headers_evaluadas],
        ["Cabeceras presentes", headers_presentes],
        ["Código retorno hsecscan", hsecscan_text],
        ["Cookies evaluables", str(cookies_count)],
        ["Hallazgos XSS mostrables", xss_count],
        [technical_files_label, str(technical_files_count)],
    ]
# ==========================================================
# ESTILOS Y TABLAS
# ==========================================================

def _build_styles() -> Dict[str, Any]:
    """
    Construye estilos de ReportLab para el PDF.
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch

    base = getSampleStyleSheet()

    return {
        "Title": ParagraphStyle(
            "DASTXHTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "SectionTitle": ParagraphStyle(
            "DASTXHSectionTitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=8,
            spaceAfter=6,
        ),
        "EvidenceTitle": ParagraphStyle(
            "DASTXHEvidenceTitle",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=12,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=4,
            spaceAfter=5,
        ),
        "BodyText": ParagraphStyle(
            "DASTXHBodyText",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.4,
            leading=13,
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "BodySmall": ParagraphStyle(
            "DASTXHBodySmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=10,
            alignment=TA_LEFT,
        ),
        "TableHeader": ParagraphStyle(
            "DASTXHTableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8,
            alignment=TA_LEFT,
            textColor=colors.white,
        ),
        "TableCell": ParagraphStyle(
            "DASTXHTableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=6.2,
            leading=7.4,
            alignment=TA_LEFT,
        ),
        "TableCellSmall": ParagraphStyle(
            "DASTXHTableCellSmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=5.8,
            leading=7.0,
            alignment=TA_LEFT,
        ),
        "BulletText": ParagraphStyle(
            "DASTXHBulletText",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.4,
            leading=13,
            leftIndent=0.18 * inch,
            firstLineIndent=-0.12 * inch,
            spaceAfter=3,
        ),
        "NoteText": ParagraphStyle(
            "DASTXHNoteText",
            parent=base["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8.1,
            leading=10,
            textColor=colors.HexColor("#475569"),
        ),
    }


def _append_key_value_table(story: List[Any], data: List[List[str]], styles: Dict[str, Any]) -> None:
    """
    Agrega una tabla de llave/valor al documento.
    """
    from reportlab.lib import colors
    from reportlab.platypus import Spacer, Table, TableStyle

    rendered_data: List[List[Any]] = []

    for key, value in data:
        rendered_data.append(
            [
                _make_paragraph(str(key), styles["TableCell"]),
                _make_paragraph(str(value), styles["BodySmall"]),
            ]
        )

    table = Table(
        rendered_data,
        colWidths=[150, 520],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF8")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 10))


def _append_text_section(
    story: List[Any],
    title: str,
    text: str,
    styles: Dict[str, Any],
) -> None:
    """
    Agrega una sección textual al PDF.
    """
    from reportlab.platypus import Spacer

    story.append(_make_paragraph(title, styles["SectionTitle"]))
    story.append(Spacer(1, 3))

    chunks = _paragraph_chunks(text)

    for chunk in chunks:
        clean_chunk = _clean_report_text(chunk)

        if clean_chunk.startswith("- ") or clean_chunk.startswith("* "):
            bullet_text = clean_chunk[2:].strip()
            story.append(_make_paragraph(f"• {bullet_text}", styles["BulletText"]))
        else:
            story.append(_make_paragraph(clean_chunk, styles["BodyText"]))

        story.append(Spacer(1, 4))

    story.append(Spacer(1, 6))


def _append_generic_evidence_table(
    story: List[Any],
    title: str,
    rows: List[Dict[str, Any]],
    columns: List[Tuple[str, str, int]],
    col_widths: List[float],
    styles: Dict[str, Any],
    max_rows: int,
    empty_message: str,
) -> None:
    """
    Agrega una tabla de evidencia al PDF.

    columns:
    - key
    - label
    - max_chars por celda
    """
    from reportlab.lib import colors
    from reportlab.platypus import LongTable, Spacer, TableStyle

    story.append(_make_paragraph(title, styles["EvidenceTitle"]))

    if not rows:
        story.append(_make_paragraph(empty_message, styles["NoteText"]))
        story.append(Spacer(1, 8))
        return

    limited_rows = rows[:max_rows]

    rendered_data: List[List[Any]] = [
        [_make_paragraph(label, styles["TableHeader"]) for _, label, _ in columns]
    ]

    for row in limited_rows:
        rendered_row: List[Any] = []

        for key, _, max_chars in columns:
            rendered_row.append(
                _cell(
                    row.get(key, "-"),
                    styles["TableCellSmall"],
                    max_chars=max_chars,
                )
            )

        rendered_data.append(rendered_row)

    table = LongTable(
        rendered_data,
        colWidths=col_widths,
        hAlign="LEFT",
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#111827")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )

    story.append(table)

    if len(rows) > max_rows:
        story.append(Spacer(1, 4))
        story.append(
            _make_paragraph(
                (
                    f"Nota: se muestran {max_rows} de {len(rows)} registros de evidencia. "
                    "La evidencia completa permanece disponible en la aplicación y archivos técnicos."
                ),
                styles["NoteText"],
            )
        )

    story.append(Spacer(1, 12))
# ==========================================================
# TABLAS DE EVIDENCIA ESPECÍFICAS
# ==========================================================

def _append_headers_evidence_table(
    story: List[Any],
    evidence: Dict[str, Any],
    styles: Dict[str, Any],
) -> None:
    """
    Agrega evidencia consolidada curl vs hsecscan.
    """
    rows = evidence.get("rows") or []
    max_rows = int(getattr(config, "PROFESSIONAL_REPORT_PDF_MAX_HEADER_EVIDENCE_ROWS", 20))

    columns = [
        ("header_name", "Cabecera", 80),
        ("classification", "Clasificación", 100),
        ("curl_status", "curl", 60),
        ("hsecscan_status", "hsecscan", 70),
        ("comparison_result", "Resultado", 110),
        ("priority", "Prioridad", 40),
        ("cwe", "CWE", 140),
        ("interpretation", "Interpretación", 260),
        ("recommendation", "Recomendación", 260),
    ]

    col_widths = [65, 80, 45, 55, 80, 45, 80, 145, 145]

    _append_generic_evidence_table(
        story=story,
        title=evidence.get("title") or "Evidencia consolidada curl vs hsecscan",
        rows=rows,
        columns=columns,
        col_widths=col_widths,
        styles=styles,
        max_rows=max_rows,
        empty_message="No hay evidencia consolidada de cabeceras disponible para esta ejecución.",
    )


def _append_cookies_evidence_table(
    story: List[Any],
    evidence: Dict[str, Any],
    styles: Dict[str, Any],
) -> None:
    """
    Agrega evidencia de cookies observadas.
    """
    rows = evidence.get("rows") or []
    max_rows = int(getattr(config, "PROFESSIONAL_REPORT_PDF_MAX_COOKIE_EVIDENCE_ROWS", 20))

    columns = [
        ("cookie", "Cookie", 100),
        ("secure", "Secure", 20),
        ("httponly", "HttpOnly", 20),
        ("samesite", "SameSite", 20),
        ("samesite_value", "Valor", 40),
        ("risk_level", "Riesgo", 40),
        ("cwe", "CWE", 140),
        ("interpretation", "Interpretación", 260),
        ("recommendation", "Recomendación", 260),
    ]

    col_widths = [75, 40, 45, 45, 55, 45, 90, 165, 175]

    _append_generic_evidence_table(
        story=story,
        title=evidence.get("title") or "Evidencia de cookies observadas",
        rows=rows,
        columns=columns,
        col_widths=col_widths,
        styles=styles,
        max_rows=max_rows,
        empty_message="No se registró evidencia de cookies observadas para esta ejecución.",
    )


def _append_xss_evidence_table(
    story: List[Any],
    evidence: Dict[str, Any],
    styles: Dict[str, Any],
) -> None:
    """
    Agrega evidencia de hallazgos XSS.
    """
    rows = evidence.get("rows") or []
    max_rows = int(getattr(config, "PROFESSIONAL_REPORT_PDF_MAX_XSS_EVIDENCE_ROWS", 20))

    columns = [
        ("row_order", "#", 20),
        ("parameter", "Parámetro", 60),
        ("payload", "Payload", 180),
        ("evidence", "Evidencia", 220),
        ("severity", "Severidad", 50),
        ("occurrences", "Ocurr.", 30),
        ("interpretation", "Interpretación", 240),
        ("risk_summary", "Riesgo", 150),
        ("likely_root_cause", "Causa probable", 140),
        ("recommended_review_area", "Revisar", 140),
    ]

    col_widths = [24, 50, 95, 110, 45, 40, 135, 75, 75, 75]

    _append_generic_evidence_table(
        story=story,
        title=evidence.get("title") or "Evidencia de hallazgos XSS",
        rows=rows,
        columns=columns,
        col_widths=col_widths,
        styles=styles,
        max_rows=max_rows,
        empty_message="No se registró evidencia XSS mostrable para esta ejecución.",
    )


def _append_evidence_for_field(
    story: List[Any],
    field: str,
    evidence_tables: Dict[str, Any],
    styles: Dict[str, Any],
) -> None:
    """
    Agrega la tabla de evidencia correspondiente a una sección editable.
    """
    if not bool(getattr(config, "PROFESSIONAL_REPORT_EVIDENCE_ENABLED", True)):
        return

    if field == "headers_analysis":
        _append_headers_evidence_table(
            story=story,
            evidence=evidence_tables.get("headers", {}),
            styles=styles,
        )
        return

    if field == "cookies_analysis":
        _append_cookies_evidence_table(
            story=story,
            evidence=evidence_tables.get("cookies", {}),
            styles=styles,
        )
        return

    if field == "xss_analysis":
        _append_xss_evidence_table(
            story=story,
            evidence=evidence_tables.get("xss", {}),
            styles=styles,
        )
        return
# ==========================================================
# CONSTRUCCIÓN DEL PDF
# ==========================================================

def _create_pdf_document(
    pdf_path: Path,
    detail: Dict[str, Any],
    version: Dict[str, Any],
) -> None:
    """
    Crea físicamente el PDF usando ReportLab.
    """
    try:
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.units import inch
        from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise RuntimeError(
            "No se encontró ReportLab dentro del contenedor. "
            "Agrega la dependencia 'reportlab' en requirements.txt o Dockerfile "
            "y reconstruye el servicio orquestador."
        ) from exc

    snapshot = _get_snapshot(version)

    pdf_context = build_professional_report_pdf_context(
        detail=detail,
        snapshot_payload=snapshot,
    )

    payload = pdf_context.get("payload", {})
    labels = pdf_context.get("labels", {})
    fields = pdf_context.get("fields", [])
    evidence_tables = pdf_context.get("evidence", {})

    styles = _build_styles()

    report_title = _safe_text(
        payload.get("report_title"),
        getattr(config, "PROFESSIONAL_REPORT_DEFAULT_TITLE", "Reporte general DASTXH"),
    )

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=landscape(letter),
        rightMargin=0.35 * inch,
        leftMargin=0.35 * inch,
        topMargin=0.42 * inch,
        bottomMargin=0.35 * inch,
        title=report_title,
        author="DASTXH",
        subject="Reporte general de evaluación dinámica de seguridad web",
    )

    story: List[Any] = []

    # Título principal.
    # Se quitó el segundo título/subtítulo para evitar repetición visual.
    story.append(_make_paragraph(report_title, styles["Title"]))
    story.append(Spacer(1, 10))

    _append_key_value_table(
        story=story,
        data=_build_metadata_table(detail, version),
        styles=styles,
    )

    _append_key_value_table(
        story=story,
        data=_build_technical_summary_table(detail),
        styles=styles,
    )

    story.append(PageBreak())

    # Secciones editables + tablas de evidencia.
    for field in fields:
        if field == "report_title":
            continue

        title = labels.get(field, field)
        text = payload.get(field, "")

        _append_text_section(
            story=story,
            title=title,
            text=text,
            styles=styles,
        )

        _append_evidence_for_field(
            story=story,
            field=field,
            evidence_tables=evidence_tables,
            styles=styles,
        )

    # Nota de trazabilidad.
    _append_text_section(
        story=story,
        title="Trazabilidad del reporte",
        text=(
            "Este PDF fue generado a partir de una versión histórica del reporte general. "
            "Las versiones anteriores del reporte pueden consultarse en la aplicación, "
            "pero no editarse. La evidencia técnica original permanece disponible en los "
            "archivos técnicos asociados a la ejecución."
        ),
        styles=styles,
    )

    doc.build(
        story,
        onFirstPage=lambda canvas, document: _build_header_footer(
            canvas,
            document,
            detail,
            version,
        ),
        onLaterPages=lambda canvas, document: _build_header_footer(
            canvas,
            document,
            detail,
            version,
        ),
    )


# ==========================================================
# API PÚBLICA DEL SERVICIO
# ==========================================================

def generate_professional_report_pdf(
    detail: Dict[str, Any],
    version: Dict[str, Any],
    reports_root: Path,
) -> Dict[str, Any]:
    """
    Genera un PDF del reporte general desde una versión histórica exacta.

    Parámetros:
    - detail:
        detalle completo de la ejecución.
    - version:
        fila de professional_report_versions que contiene snapshot_json.
    - reports_root:
        normalmente /work/reports.

    Retorna:
    {
      "ok": true,
      "run_id": "...",
      "pdf_file_name": "...",
      "pdf_path": "...",
      "pdf_relative_path": "...",
      "size_bytes": 12345
    }
    """
    version_number = int(version.get("version_number") or 1)
    run_folder_name = _get_run_folder_name(detail)

    output_dir = _resolve_output_directory(
        detail=detail,
        reports_root=Path(reports_root),
    )

    _ensure_directory(output_dir)

    pdf_file_name = _build_pdf_file_name(version_number)
    pdf_path = output_dir / pdf_file_name

    _create_pdf_document(
        pdf_path=pdf_path,
        detail=detail,
        version=version,
    )

    if not pdf_path.exists():
        raise RuntimeError("El PDF del reporte general no fue creado correctamente.")

    size_bytes = pdf_path.stat().st_size

    if size_bytes <= 0:
        raise RuntimeError("El PDF del reporte general fue creado vacío.")

    return {
        "ok": True,
        "run_id": run_folder_name,
        "pdf_file_name": pdf_file_name,
        "pdf_path": str(pdf_path),
        "pdf_relative_path": _build_relative_path(run_folder_name, pdf_file_name),
        "size_bytes": size_bytes,
    }