"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.

Esta versión:
- mantiene una GUI minimalista
- usa una sola URL objetivo
- elimina la selección manual de perfil desde la GUI
- fuerza internamente un flujo profundo controlado
- habilita hsecscan como parte del flujo estándar
- integra el Reporte General Profesional:
    * contexto para pestaña Reporte general
    * generación de borrador asistido por IA
    * guardado editable con versionamiento histórico
    * impresión/exportación PDF trazable

Regla del reporte general:
- professional_reports guarda la versión actual editable.
- professional_report_versions conserva el historial de solo lectura.
- professional_report_pdf_exports registra cada PDF generado.
- artifacts registra el archivo físico PDF como evidencia de la ejecución.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import db as db_layer
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.routes_history import router as history_router
from api.routes_reports import router as reports_router
from api.routes_scans import router as scans_router
from services.ai_report_service import generate_professional_report_with_ai
from services.professional_report_pdf_service import generate_professional_report_pdf
from services.professional_report_service import (
    build_professional_report_view_context,
    normalize_professional_report_payload,
)
from services.scanner_service import start_scan_in_background
from utils import ensure_dir, wait_for_db


# ==========================================================
# CONFIGURACIÓN FUNCIONAL DEL FLUJO WEB
# ==========================================================

STANDARD_SCAN_PROFILE = "profundo"
STANDARD_ENABLE_HSECSCAN = True


# ==========================================================
# RUTAS BASE DEL PROYECTO
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"

WORKDIR = Path(os.getenv("WORKDIR", "/work"))
REPORTS_DIR = WORKDIR / "reports"


# ==========================================================
# APP FASTAPI
# ==========================================================

app = FastAPI(
    title="DASTXH Web",
    version="0.4.0",
    description="GUI web para DASTXH con flujo profundo controlado y reporte general profesional",
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Middleware simple para agregar cabeceras de seguridad
    a las respuestas generadas por la GUI web/API.
    """
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app.include_router(scans_router)
app.include_router(history_router)
app.include_router(reports_router)


# ==========================================================
# HELPERS INTERNOS
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
    - El usuario ya no elige entre superficial/profundo.
    - La GUI ejecuta siempre el flujo profundo controlado.
    - El campo scan_profile se conserva en BD como dato técnico
      para no romper historial ni consultas existentes.
    """
    return STANDARD_SCAN_PROFILE


def get_standard_hsecscan_enabled() -> bool:
    """
    Devuelve si hsecscan debe ejecutarse en el flujo estándar.

    En el flujo profundo controlado, hsecscan queda habilitado
    como segunda capa de contraste para cabeceras HTTP.
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

    La ruta /api/reports/file/{run_id}/{file_name} ya sirve artifacts
    desde la carpeta de reportes.
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


# ==========================================================
# RUTAS WEB
# ==========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Página principal.
    """
    recent_executions = load_recent_executions(limit=10)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "DASTXH - Inicio",
            "default_timeout": get_default_timeout(),
            "recent_executions": recent_executions,
        },
    )


@app.post("/scan")
def start_scan(
    request: Request,
    url: str = Form(...),
    timeout: Optional[int] = Form(default=None),
):
    """
    Inicia un escaneo desde la GUI web.

    Regla actual:
    - el usuario solo ingresa la URL y timeout base;
    - DASTXH ejecuta internamente el flujo profundo controlado;
    - hsecscan queda habilitado como parte del flujo estándar.
    """
    target_url = validate_target_url(url)
    timeout_s = timeout if timeout is not None else get_default_timeout()

    ensure_work_paths()
    dsn = wait_until_db_ready(timeout_s=20)

    result = start_scan_in_background(
        dsn=dsn,
        workdir=WORKDIR,
        url=target_url,
        timeout_s=timeout_s,
        request_source="web",
        scan_profile=get_standard_scan_profile(),
        enable_hsecscan=get_standard_hsecscan_enabled(),
    )

    execution_id = result.get("execution_id")

    if execution_id is None:
        raise HTTPException(status_code=500, detail="No se obtuvo execution_id.")

    return RedirectResponse(
        url=f"/executions/{execution_id}",
        status_code=303,
    )


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request):
    """
    Página de historial de ejecuciones.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    executions = db_layer.list_execution_summaries(dsn=dsn, limit=100, offset=0)
    runs = [str(item["id"]) for item in executions]

    return templates.TemplateResponse(
        "history.html",
        {
            "request": request,
            "title": "DASTXH - Historial",
            "runs": runs,
            "executions": executions,
        },
    )


@app.get("/executions/{execution_id}", response_class=HTMLResponse)
def execution_detail(request: Request, execution_id: int):
    """
    Página de detalle de una ejecución.

    También prepara el contexto de la pestaña Reporte general.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    artifacts = detail.get("artifacts", [])
    files = [str(item.get("file_name", "")) for item in artifacts if item.get("file_name")]
    run_id = get_report_folder_name(detail.get("report_dir"))

    professional_report_view = build_professional_report_view_context(
        detail=detail,
        current_report=detail.get("professional_report"),
    )

    return templates.TemplateResponse(
        "execution_detail.html",
        {
            "request": request,
            "title": f"DASTXH - Ejecución {execution_id}",
            "execution_id": execution_id,
            "run_id": run_id,
            "files": files,
            "detail": detail,
            "artifacts": artifacts,
            "professional_report_view": professional_report_view,
        },
    )


# ==========================================================
# RUTAS WEB: REPORTE GENERAL PROFESIONAL
# ==========================================================

@app.post("/executions/{execution_id}/professional-report/generate")
def generate_professional_report(request: Request, execution_id: int):
    """
    Genera o reemplaza el borrador actual del reporte general usando IA.

    Comportamiento:
    - toma datos técnicos ya persistidos;
    - solicita redacción asistida por IA;
    - si la IA falla, usa fallback determinístico;
    - guarda el contenido como versión actual editable;
    - crea una versión histórica.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    generation_result = generate_professional_report_with_ai(detail)
    payload = generation_result.get("payload") or {}

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=500,
            detail="No fue posible generar el contenido del reporte general.",
        )

    used_ai = bool(generation_result.get("used_ai"))
    model_name = generation_result.get("model_name")

    if used_ai:
        change_reason = "Borrador generado con asistencia de IA para reporte general."
        change_type = getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_AI_GENERATED",
            "ai_generated",
        )
    else:
        error_text = generation_result.get("error")
        change_reason = (
            "Borrador generado con plantilla determinística porque la IA no se usó "
            "o no respondió correctamente."
        )

        if error_text:
            change_reason = f"{change_reason} Detalle: {error_text}"

        change_type = getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE",
            "manual_save",
        )

    db_layer.save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=used_ai,
        ai_model_name=model_name if used_ai else None,
        change_type=change_type,
        change_reason=change_reason,
        updated_by="web",
    )

    return redirect_to_execution_report_tab(execution_id)


@app.post("/executions/{execution_id}/professional-report/save")
async def save_professional_report(request: Request, execution_id: int):
    """
    Guarda cambios manuales del formulario editable.

    Cada guardado:
    - actualiza professional_reports;
    - crea una nueva fila en professional_report_versions;
    - deja versiones anteriores como solo lectura.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    # Verifica que la ejecución exista antes de guardar.
    load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    form = await request.form()
    form_data = dict(form)

    payload = build_report_payload_from_form(form_data)

    db_layer.save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=False,
        ai_model_name=None,
        change_type=getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE",
            "manual_save",
        ),
        change_reason="Cambios guardados manualmente desde la pestaña Reporte general.",
        updated_by="web",
    )

    return redirect_to_execution_report_tab(execution_id)


@app.post("/executions/{execution_id}/professional-report/print")
async def print_professional_report(request: Request, execution_id: int):
    """
    Imprime/exporta el Reporte General Profesional a PDF.

    Flujo:
    1. Lee el formulario actual.
    2. Guarda esos datos como versión histórica tipo pdf_export_snapshot.
    3. Genera el PDF desde esa versión exacta.
    4. Registra el PDF como artifact.
    5. Registra la exportación en professional_report_pdf_exports.
    6. Redirige al PDF generado.

    Esto garantiza trazabilidad:
    - el PDF queda asociado a una versión histórica inmutable;
    - el archivo queda en artifacts;
    - la exportación queda registrada en BD.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    # Carga inicial para verificar existencia y obtener report_dir.
    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    form = await request.form()
    form_data = dict(form)
    payload = build_report_payload_from_form(form_data)

    # Crea una versión histórica específica para este PDF.
    pdf_version = db_layer.create_professional_report_pdf_snapshot_version(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        change_reason="Versión histórica creada automáticamente para impresión/exportación PDF.",
        created_by="web",
    )

    # Recarga detalle para que el PDF use datos actualizados y el reporte actual ya guardado.
    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    pdf_result = generate_professional_report_pdf(
        detail=detail,
        version=pdf_version,
        reports_root=REPORTS_DIR,
    )

    pdf_file_name = str(pdf_result.get("pdf_file_name") or "")
    pdf_relative_path = str(pdf_result.get("pdf_relative_path") or "")
    run_id = str(pdf_result.get("run_id") or get_report_folder_name(detail.get("report_dir")) or "")
    size_bytes = int(pdf_result.get("size_bytes") or 0)

    if not pdf_file_name or not pdf_relative_path:
        raise HTTPException(
            status_code=500,
            detail="El PDF fue generado, pero no se obtuvo nombre o ruta relativa.",
        )

    professional_report = db_layer.get_professional_report(
        dsn=dsn,
        execution_id=execution_id,
    )

    if not professional_report:
        raise HTTPException(
            status_code=500,
            detail="No se encontró el reporte general después de generar la versión PDF.",
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
        professional_report_id=int(professional_report["id"]),
        professional_report_version_id=int(pdf_version["id"]),
        execution_id=execution_id,
        artifact_id=artifact_id if artifact_id > 0 else None,
        pdf_file_name=pdf_file_name,
        pdf_relative_path=pdf_relative_path,
        exported_by="web",
    )

    return redirect_to_generated_pdf(run_id=run_id, pdf_file_name=pdf_file_name)


@app.get("/executions/{execution_id}/professional-report/versions/{version_id}", response_class=HTMLResponse)
def view_professional_report_version(
    request: Request,
    execution_id: int,
    version_id: int,
):
    """
    Consulta una versión histórica del reporte general.

    Regla:
    - Las versiones históricas son solo lectura.
    - No existe ruta POST para editarlas.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    version = db_layer.get_professional_report_version(
        dsn=dsn,
        version_id=version_id,
    )

    if not version or int(version.get("execution_id") or 0) != execution_id:
        raise HTTPException(status_code=404, detail="Versión histórica no encontrada.")

    artifacts = detail.get("artifacts", [])
    files = [str(item.get("file_name", "")) for item in artifacts if item.get("file_name")]
    run_id = get_report_folder_name(detail.get("report_dir"))

    professional_report_view = build_professional_report_view_context(
        detail=detail,
        current_report=detail.get("professional_report"),
    )

    return templates.TemplateResponse(
        "execution_detail.html",
        {
            "request": request,
            "title": f"DASTXH - Versión histórica {version.get('version_number')}",
            "execution_id": execution_id,
            "run_id": run_id,
            "files": files,
            "detail": detail,
            "artifacts": artifacts,
            "professional_report_view": professional_report_view,
            "readonly_report_version": version,
        },
    )


# ==========================================================
# RUTA DE SALUD
# ==========================================================

@app.get("/health")
def health() -> Dict[str, Any]:
    """
    Verificación simple del estado de la app web.
    """
    db_ok = False

    try:
        dsn = get_dsn()
        db_layer.ping_db(dsn)
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "ok": True,
        "app": "dastxh-web",
        "db_ok": db_ok,
        "standard_scan_profile": STANDARD_SCAN_PROFILE,
        "standard_hsecscan_enabled": STANDARD_ENABLE_HSECSCAN,
        "professional_report_enabled": True,
        "professional_report_pdf_enabled": True,
    }