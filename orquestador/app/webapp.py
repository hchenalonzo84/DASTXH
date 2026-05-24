"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.

Esta versión:
- mantiene una GUI minimalista;
- usa una sola URL objetivo;
- elimina la selección manual de perfil desde la GUI;
- fuerza internamente un flujo profundo controlado;
- habilita hsecscan como parte del flujo estándar;
- integra el Reporte General:
    * contexto para pestaña Reporte general;
    * generación de borrador asistido por IA;
    * guardado editable con versionamiento histórico;
    * impresión/exportación PDF trazable;
    * impresión de versiones históricas específicas;
- registra filtros globales de Jinja para:
    * mostrar fechas en hora local de Guatemala;
    * traducir estados internos a español;
    * traducir tipos de versión a español.

Cambio de refactorización:
- La lógica de fechas y traducción de estados ya no vive aquí.
- Ahora se centraliza en utils/datetime_utils.py y se reexporta desde utils/__init__.py.

Regla global de fechas:
- PostgreSQL puede conservar las fechas en UTC.
- DASTXH debe mostrar fechas en America/Guatemala.
- Las plantillas HTML no deben usar .strftime(...) directamente.
  Deben usar el filtro:
      {{ valor_fecha|local_datetime }}
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
    version="0.4.3",
    description=(
        "GUI web para DASTXH con flujo profundo controlado, "
        "reporte general versionado, exportación PDF y fechas locales"
    ),
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
# FILTROS GLOBALES PARA PLANTILLAS JINJA
# ==========================================================

templates.env.filters["local_datetime"] = format_local_datetime
templates.env.filters["execution_status_label"] = execution_status_label
templates.env.filters["professional_report_status_label"] = professional_report_status_label
templates.env.filters["report_change_type_label"] = report_change_type_label


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
    - la versión debe existir;
    - la versión debe pertenecer a la ejecución indicada.
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

    Nota:
    - request_source se conserva con valor "web" en BD por compatibilidad,
      pero ya no es necesario mostrarlo como tarjeta en la GUI.
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
# RUTAS WEB: REPORTE GENERAL
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
    Imprime/exporta el Reporte General a PDF desde el formulario actual.

    Esta ruta se conserva por compatibilidad.

    En la GUI nueva, lo recomendable es:
    - guardar primero;
    - luego imprimir una versión histórica ya guardada.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    form = await request.form()
    form_data = dict(form)
    payload = build_report_payload_from_form(form_data)

    pdf_version = db_layer.create_professional_report_pdf_snapshot_version(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        change_reason="Versión histórica creada automáticamente para impresión/exportación PDF.",
        created_by="web",
    )

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    pdf_result = register_professional_report_pdf_from_version(
        dsn=dsn,
        execution_id=execution_id,
        detail=detail,
        version=pdf_version,
        exported_by="web",
    )

    return redirect_to_generated_pdf(
        run_id=str(pdf_result.get("run_id") or ""),
        pdf_file_name=str(pdf_result.get("pdf_file_name") or ""),
    )


@app.post("/executions/{execution_id}/professional-report/versions/{version_id}/print")
def print_professional_report_version(
    request: Request,
    execution_id: int,
    version_id: int,
):
    """
    Imprime/exporta una versión histórica específica del Reporte General.

    Ventajas:
    - no modifica el contenido actual editable;
    - no crea una versión nueva innecesaria;
    - permite imprimir versiones antiguas;
    - mantiene trazabilidad: PDF -> versión histórica exacta.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    version = load_professional_report_version_or_404(
        dsn=dsn,
        execution_id=execution_id,
        version_id=version_id,
    )

    pdf_result = register_professional_report_pdf_from_version(
        dsn=dsn,
        execution_id=execution_id,
        detail=detail,
        version=version,
        exported_by="web",
    )

    return redirect_to_generated_pdf(
        run_id=str(pdf_result.get("run_id") or ""),
        pdf_file_name=str(pdf_result.get("pdf_file_name") or ""),
    )


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
    - La versión histórica consultada también puede imprimirse desde la GUI.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    version = load_professional_report_version_or_404(
        dsn=dsn,
        execution_id=execution_id,
        version_id=version_id,
    )

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
        "display_timezone": getattr(config, "DISPLAY_TIMEZONE", "America/Guatemala"),
        "professional_report_enabled": True,
        "professional_report_pdf_enabled": True,
        "professional_report_version_pdf_enabled": True,
    }