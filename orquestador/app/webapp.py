"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.

Esta versión:
- mantiene una GUI minimalista;
- registra routers API y web;
- expone health check general;
- monta archivos estáticos;
- aplica middleware de cabeceras de seguridad.

Cambio de refactorización:
- Las utilidades compartidas viven en api/web_common.py.
- La ruta Inicio vive en api/routes_home.py.
- La ruta POST /scan vive en api/routes_web_scan.py.
- La ruta web de historial vive en api/routes_web_history.py.
- La ruta de detalle de ejecución vive en api/routes_execution_detail.py.
- Las rutas del Reporte General viven en api/routes_professional_report.py.
- Los filtros Jinja se registran desde api/web_common.py.
"""

from __future__ import annotations

from typing import Any, Dict

import config
import db as db_layer
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from api.routes_execution_detail import router as execution_detail_router
from api.routes_history import router as history_router
from api.routes_home import router as home_router
from api.routes_professional_report import router as professional_report_router
from api.routes_reports import router as reports_router
from api.routes_scans import router as scans_router
from api.routes_web_history import router as web_history_router
from api.routes_web_scan import router as web_scan_router
from api.web_common import (
    STATIC_DIR,
    get_dsn,
    get_standard_hsecscan_enabled,
    get_standard_scan_profile,
)


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
# STATIC
# ==========================================================

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ==========================================================
# ROUTERS API
# ==========================================================

app.include_router(scans_router)
app.include_router(history_router)
app.include_router(reports_router)


# ==========================================================
# ROUTERS WEB
# ==========================================================

app.include_router(home_router)
app.include_router(web_scan_router)
app.include_router(web_history_router)
app.include_router(execution_detail_router)
app.include_router(professional_report_router)


# ==========================================================
# RUTA DE SALUD GENERAL
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