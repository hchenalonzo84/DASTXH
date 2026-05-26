"""
web_common.py
- Helpers compartidos para rutas web de DASTXH.

Objetivo:
- Evitar que webapp.py concentre toda la lógica auxiliar.
- Compartir configuración de rutas, plantillas, carpetas y helpers comunes.
- Permitir mover rutas a módulos separados sin crear imports circulares.

Este módulo NO define una app FastAPI.
Solo define:
- rutas base;
- objeto templates;
- filtros Jinja;
- helpers de BD;
- helpers de archivos;
- helpers del reporte general.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import db as db_layer
from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from services.professional_report_pdf_service import generate_professional_report_pdf
from services.professional_report_service import normalize_professional_report_payload
from utils import (
    ensure_dir,
    execution_status_label,
    format_local_datetime,
    professional_report_status_label,
    report_change_type_label,
    wait_for_db,
)


# ==========================================================
# CONFIGURACIÓN FUNCIONAL DEL FLUJO WEB
# ==========================================================

STANDARD_SCAN_PROFILE = "profundo"
STANDARD_ENABLE_HSECSCAN = True


# ==========================================================
# RUTAS BASE DEL PROYECTO
# ==========================================================

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"

WORKDIR = Path(os.getenv("WORKDIR", "/work"))
REPORTS_DIR = WORKDIR / "reports"


# ==========================================================
# PLANTILLAS JINJA
# ==========================================================

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Filtros globales disponibles para todas las plantillas.
templates.env.filters["local_datetime"] = format_local_datetime
templates.env.filters["execution_status_label"] = execution_status_label
templates.env.filters["professional_report_status_label"] = professional_report_status_label
templates.env.filters["report_change_type_label"] = report_change_type_label


# ==========================================================
# HELPERS GENERALES
# ==========================================================

def get_dsn() -> str:
    """
    Obtiene la cadena de conexión desde DATABASE_URL.
    """
    dsn = os.getenv("DATABASE_URL")

    if not dsn:
        raise RuntimeError("DATABASE_URL no está configurada.")

    return dsn


def get_default_timeout() -> int:
    """
    Obtiene el timeout por defecto configurado para el backend.
    """
    return int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30"))


def ensure_work_paths() -> None:
    """
    Garantiza que existan las carpetas base de trabajo.
    """
    ensure_dir(WORKDIR)
    ensure_dir(REPORTS_DIR)


def get_report_folder_name(report_dir: Optional[str]) -> str:
    """
    Extrae el nombre final de carpeta desde una ruta lógica.

    Ejemplo:
        /work/reports/20260520_213452 -> 20260520_213452
    """
    if not report_dir:
        return ""

    return Path(report_dir).name


def validate_target_url(value: str) -> str:
    """
    Validación mínima de la URL ingresada desde la GUI.
    """
    target_url = (value or "").strip()

    if not target_url:
        raise HTTPException(status_code=400, detail="La URL no puede estar vacía.")

    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        raise HTTPException(
            status_code=400,
            detail="La URL debe iniciar con http:// o https://",
        )

    return target_url


def get_standard_scan_profile() -> str:
    """
    Devuelve el perfil estándar usado por DASTXH.

    Decisión de diseño:
    - La GUI ejecuta siempre el flujo profundo controlado.
    - El campo scan_profile se conserva en BD por compatibilidad.
    """
    return STANDARD_SCAN_PROFILE


def get_standard_hsecscan_enabled() -> bool:
    """
    Devuelve si hsecscan debe ejecutarse en el flujo estándar.
    """
    return STANDARD_ENABLE_HSECSCAN


def wait_until_db_ready(timeout_s: int = 20) -> str:
    """
    Espera a que la base de datos esté disponible y devuelve el DSN.
    """
    dsn = get_dsn()
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=timeout_s)
    return dsn


def load_recent_executions(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Carga ejecuciones recientes desde la vista de resumen.

    Si la BD aún no está lista, devuelve lista vacía para no romper Inicio.
    """
    try:
        dsn = wait_until_db_ready(timeout_s=10)
        return db_layer.list_execution_summaries(dsn=dsn, limit=limit, offset=0)
    except Exception:
        return []


def load_execution_detail_or_404(dsn: str, execution_id: int) -> Dict[str, Any]:
    """
    Carga el detalle de una ejecución o lanza 404.
    """
    detail = db_layer.get_execution_detail(dsn=dsn, execution_id=execution_id)

    if not detail:
        raise HTTPException(status_code=404, detail="Ejecución no encontrada.")

    return detail


# ==========================================================
# HELPERS DEL REPORTE GENERAL
# ==========================================================

def build_report_payload_from_form(form_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Construye el payload editable del reporte general a partir del formulario.

    Solo acepta campos definidos en config.PROFESSIONAL_REPORT_EDITABLE_FIELDS
    para evitar guardar datos inesperados.
    """
    raw_payload: Dict[str, Any] = {}

    for field in getattr(config, "PROFESSIONAL_REPORT_EDITABLE_FIELDS", []):
        raw_payload[field] = form_data.get(field, "")

    return normalize_professional_report_payload(raw_payload)


def redirect_to_execution_report_tab(execution_id: int) -> RedirectResponse:
    """
    Redirige al detalle de ejecución con hash de la pestaña Reporte general.
    """
    return RedirectResponse(
        url=f"/executions/{execution_id}#general-report-pane",
        status_code=303,
    )


def redirect_to_generated_pdf(run_id: str, pdf_file_name: str) -> RedirectResponse:
    """
    Redirige al archivo PDF recién generado.
    """
    if not run_id or not pdf_file_name:
        raise HTTPException(
            status_code=500,
            detail="No fue posible construir la ruta del PDF generado.",
        )

    return RedirectResponse(
        url=f"/api/reports/file/{run_id}/{pdf_file_name}",
        status_code=303,
    )


def load_professional_report_version_or_404(
    dsn: str,
    execution_id: int,
    version_id: int,
) -> Dict[str, Any]:
    """
    Carga una versión histórica del reporte general o lanza 404.

    Validación:
    - La versión debe existir.
    - La versión debe pertenecer a la ejecución indicada.
    """
    version = db_layer.get_professional_report_version(
        dsn=dsn,
        version_id=version_id,
    )

    if not version:
        raise HTTPException(
            status_code=404,
            detail="Versión histórica no encontrada.",
        )

    if int(version.get("execution_id") or 0) != int(execution_id):
        raise HTTPException(
            status_code=404,
            detail="La versión histórica no pertenece a esta ejecución.",
        )

    return version


def register_professional_report_pdf_from_version(
    dsn: str,
    execution_id: int,
    detail: Dict[str, Any],
    version: Dict[str, Any],
    exported_by: str = "web",
) -> Dict[str, Any]:
    """
    Genera y registra un PDF desde una versión histórica específica.

    Pasos:
    1. Genera el PDF físico.
    2. Registra el PDF como archivo técnico.
    3. Registra la exportación en professional_report_pdf_exports.
    4. Devuelve la información necesaria para abrir el PDF.
    """
    professional_report_id = int(version.get("professional_report_id") or 0)

    if professional_report_id <= 0:
        professional_report = db_layer.get_professional_report(
            dsn=dsn,
            execution_id=execution_id,
        )

        if not professional_report:
            raise HTTPException(
                status_code=500,
                detail="No se encontró el reporte general asociado a la versión.",
            )

        professional_report_id = int(professional_report["id"])

    pdf_result = generate_professional_report_pdf(
        detail=detail,
        version=version,
        reports_root=REPORTS_DIR,
    )

    pdf_file_name = str(pdf_result.get("pdf_file_name") or "")
    pdf_relative_path = str(pdf_result.get("pdf_relative_path") or "")
    run_id = str(
        pdf_result.get("run_id")
        or get_report_folder_name(detail.get("report_dir"))
        or ""
    )
    size_bytes = int(pdf_result.get("size_bytes") or 0)

    if not pdf_file_name or not pdf_relative_path:
        raise HTTPException(
            status_code=500,
            detail="El PDF fue generado, pero no se obtuvo nombre o ruta relativa.",
        )

    artifact_id = db_layer.register_artifact(
        dsn=dsn,
        execution_id=execution_id,
        artifact_type=getattr(
            config,
            "ARTIFACT_TYPE_PROFESSIONAL_REPORT_PDF",
            "professional_report_pdf",
        ),
        file_name=pdf_file_name,
        relative_path=pdf_relative_path,
        mime_type=getattr(config, "MIME_APPLICATION_PDF", "application/pdf"),
        size_bytes=size_bytes,
    )

    db_layer.register_professional_report_pdf_export(
        dsn=dsn,
        professional_report_id=professional_report_id,
        professional_report_version_id=int(version["id"]),
        execution_id=execution_id,
        artifact_id=artifact_id if artifact_id > 0 else None,
        pdf_file_name=pdf_file_name,
        pdf_relative_path=pdf_relative_path,
        exported_by=exported_by,
    )

    pdf_result["run_id"] = run_id
    return pdf_result