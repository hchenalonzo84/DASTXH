"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.

Esta versión:
- mantiene una GUI minimalista;
- usa una sola URL objetivo;
- elimina la selección manual de perfil desde la GUI;
- fuerza internamente un flujo profundo controlado;
- habilita hsecscan como parte del flujo estándar;
- registra routers API y web;
- conserva aquí solamente rutas web principales:
    * Inicio;
    * iniciar evaluación desde GUI;
    * historial;
    * detalle de ejecución;
    * health.

Cambio de refactorización:
- Las utilidades compartidas viven en api/web_common.py.
- Las rutas del Reporte General viven en api/routes_professional_report.py.
- Los filtros Jinja se registran desde api/web_common.py.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import config
import db as db_layer
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from api.routes_history import router as history_router
from api.routes_professional_report import router as professional_report_router
from api.routes_reports import router as reports_router
from api.routes_scans import router as scans_router
from api.web_common import (
    STATIC_DIR,
    WORKDIR,
    ensure_work_paths,
    get_default_timeout,
    get_dsn,
    get_report_folder_name,
    get_standard_hsecscan_enabled,
    get_standard_scan_profile,
    load_execution_detail_or_404,
    load_recent_executions,
    templates,
    validate_target_url,
    wait_until_db_ready,
)
from services.professional_report_service import build_professional_report_view_context
from services.scanner_service import start_scan_in_background


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


# ==========================================================
# STATIC + ROUTERS
# ==========================================================

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.include_router(scans_router)
app.include_router(history_router)
app.include_router(reports_router)
app.include_router(professional_report_router)


# ==========================================================
# RUTAS WEB PRINCIPALES
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
    files = [
        str(item.get("file_name", ""))
        for item in artifacts
        if item.get("file_name")
    ]
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
        "standard_scan_profile": get_standard_scan_profile(),
        "standard_hsecscan_enabled": get_standard_hsecscan_enabled(),
        "display_timezone": getattr(config, "DISPLAY_TIMEZONE", "America/Guatemala"),
        "professional_report_enabled": True,
        "professional_report_pdf_enabled": True,
        "professional_report_version_pdf_enabled": True,
    }