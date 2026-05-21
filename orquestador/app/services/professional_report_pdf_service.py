"""
professional_report_pdf_service.py
- Servicio para generar el PDF del Reporte General Profesional de DASTXH.

Objetivo:
- Tomar una versión histórica exacta del reporte general.
- Generar un PDF profesional a partir de esa versión.
- Guardar el PDF en la carpeta de artifacts de la ejecución:
    /work/reports/<run_id>/reporte_general_vX_YYYYMMDD_HHMMSS.pdf

Importante:
- Este archivo NO llama IA.
- Este archivo NO modifica la base de datos.
- Este archivo NO registra artifacts.
- Este archivo NO decide contenido técnico.
- Solo toma texto ya guardado/versionado y lo convierte a PDF.

Flujo esperado:
1. webapp.py recibe POST /executions/{id}/professional-report/print
2. webapp.py guarda primero los cambios actuales.
3. db.py crea una versión histórica tipo pdf_export_snapshot.
4. professional_report_pdf_service.py genera el PDF desde esa versión.
5. webapp.py registra el PDF en artifacts.
6. webapp.py registra la exportación en professional_report_pdf_exports.
"""

from __future__ import annotations

import html
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import config


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


def _format_datetime(value: Any) -> str:
    """
    Formatea fechas de forma tolerante.

    Acepta:
    - datetime
    - string
    - None
    """
    if value is None:
        return "-"

    if hasattr(value, "strftime"):
        try:
            return value.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(value)

    return str(value)


def _sanitize_filename_part(value: Any, default: str = "reporte") -> str:
    """
    Limpia una parte de nombre de archivo para evitar caracteres problemáticos.
    """
    text = _safe_text(value, default).lower()

    # Reemplazos básicos para nombres amigables.
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
    Construye una ruta relativa lógica para registrar como artifact.
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


def _get_editable_fields() -> List[str]:
    """
    Devuelve campos editables del reporte general.
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


def _get_section_labels() -> Dict[str, str]:
    """
    Devuelve etiquetas amigables para las secciones del reporte.
    """
    labels = getattr(config, "PROFESSIONAL_REPORT_SECTION_LABELS", {})

    if isinstance(labels, dict):
        return {str(k): str(v) for k, v in labels.items()}

    return {field: field for field in _get_editable_fields()}


def _clean_report_text(value: Any) -> str:
    """
    Limpia texto para evitar caracteres que puedan dar problemas visuales.

    No elimina tildes ni caracteres normales en español.
    """
    text = _safe_text(value)

    # Normaliza saltos de línea.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Evita caracteres de control.
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)

    return text.strip()


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

        # Si parece viñeta, se trata como bloque individual.
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

    ReportLab Paragraph acepta un subconjunto HTML.
    """
    escaped = html.escape(text)
    escaped = escaped.replace("\n", "<br/>")
    return escaped


# ==========================================================
# CONSTRUCCIÓN DEL PDF
# ==========================================================

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
    canvas.drawString(doc.leftMargin, height - 28, header_text)

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - doc.rightMargin, 20, footer_text)

    canvas.restoreState()


def _build_metadata_table(detail: Dict[str, Any], version: Dict[str, Any]) -> List[List[str]]:
    """
    Construye una tabla simple de metadatos del reporte.
    """
    return [
        ["Ejecución", _safe_text(detail.get("id"), "-")],
        ["URL objetivo", _safe_text(detail.get("target_url"), "-")],
        ["Estado de ejecución", _safe_text(detail.get("status"), "-")],
        ["Flujo aplicado", "Evaluación profunda controlada"],
        ["Inicio", _format_datetime(detail.get("started_at"))],
        ["Fin", _format_datetime(detail.get("finished_at"))],
        ["Versión del reporte", _safe_text(version.get("version_label"), "-")],
        ["Tipo de versión", _safe_text(version.get("change_type"), "-")],
        ["Fecha de versión", _format_datetime(version.get("created_at"))],
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
    artifacts_count = len(detail.get("artifacts") or [])

    return [
        ["Cumplimiento de cabeceras", cumplimiento_text],
        ["Cabeceras evaluadas", headers_evaluadas],
        ["Cabeceras presentes", headers_presentes],
        ["Código retorno hsecscan", hsecscan_text],
        ["Cookies evaluables", str(cookies_count)],
        ["Hallazgos XSS mostrables", xss_count],
        ["Artifacts registrados", str(artifacts_count)],
    ]


def _append_table(story: List[Any], data: List[List[str]], styles: Dict[str, Any]) -> None:
    """
    Agrega una tabla al documento.
    """
    from reportlab.lib import colors
    from reportlab.platypus import Spacer, Table, TableStyle

    normal_style = styles["BodySmall"]

    rendered_data: List[List[Any]] = []

    for key, value in data:
        rendered_data.append(
            [
                _make_paragraph(str(key), styles["TableHeader"]),
                _make_paragraph(str(value), normal_style),
            ]
        )

    table = Table(
        rendered_data,
        colWidths=[150, 350],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF8")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 12))


def _make_paragraph(text: str, style: Any) -> Any:
    """
    Crea un Paragraph seguro.
    """
    from reportlab.platypus import Paragraph

    return Paragraph(_to_reportlab_html(text), style)


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
    story.append(Spacer(1, 4))

    chunks = _paragraph_chunks(text)

    for chunk in chunks:
        clean_chunk = _clean_report_text(chunk)

        if clean_chunk.startswith("- ") or clean_chunk.startswith("* "):
            bullet_text = clean_chunk[2:].strip()
            story.append(_make_paragraph(f"• {bullet_text}", styles["BulletText"]))
        else:
            story.append(_make_paragraph(clean_chunk, styles["BodyText"]))

        story.append(Spacer(1, 5))

    story.append(Spacer(1, 8))


def _build_styles() -> Dict[str, Any]:
    """
    Construye estilos de ReportLab para el PDF.
    """
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
            spaceAfter=10,
        ),
        "Subtitle": ParagraphStyle(
            "DASTXHSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            alignment=TA_CENTER,
            textColor="#334155",
            spaceAfter=14,
        ),
        "SectionTitle": ParagraphStyle(
            "DASTXHSectionTitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            alignment=TA_LEFT,
            textColor="#0F172A",
            spaceBefore=8,
            spaceAfter=6,
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
            fontSize=8.6,
            leading=11,
            alignment=TA_LEFT,
        ),
        "TableHeader": ParagraphStyle(
            "DASTXHTableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.7,
            leading=11,
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
    }


def _create_pdf_document(
    pdf_path: Path,
    detail: Dict[str, Any],
    version: Dict[str, Any],
) -> None:
    """
    Crea físicamente el PDF usando ReportLab.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.platypus import PageBreak, SimpleDocTemplate, Spacer
    except ImportError as exc:
        raise RuntimeError(
            "No se encontró ReportLab dentro del contenedor. "
            "Agrega la dependencia 'reportlab' en requirements.txt o Dockerfile "
            "y reconstruye el servicio orquestador."
        ) from exc

    snapshot = _get_snapshot(version)
    labels = _get_section_labels()
    fields = _get_editable_fields()
    styles = _build_styles()

    report_title = _safe_text(
        snapshot.get("report_title"),
        getattr(config, "PROFESSIONAL_REPORT_DEFAULT_TITLE", "Reporte general DASTXH"),
    )

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.55 * inch,
        title=report_title,
        author="DASTXH",
        subject="Reporte general profesional de evaluación dinámica de seguridad web",
    )

    story: List[Any] = []

    # Portada simple.
    story.append(_make_paragraph(report_title, styles["Title"]))
    story.append(
        _make_paragraph(
            "Reporte general profesional generado por DASTXH",
            styles["Subtitle"],
        )
    )
    story.append(Spacer(1, 10))

    _append_table(
        story=story,
        data=_build_metadata_table(detail, version),
        styles=styles,
    )

    story.append(Spacer(1, 4))

    _append_table(
        story=story,
        data=_build_technical_summary_table(detail),
        styles=styles,
    )

    story.append(PageBreak())

    # Secciones editables del reporte.
    for field in fields:
        if field == "report_title":
            continue

        title = labels.get(field, field)
        text = snapshot.get(field, "")

        _append_text_section(
            story=story,
            title=title,
            text=text,
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
            "artifacts asociados a la ejecución."
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