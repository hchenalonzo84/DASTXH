"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.

Esta versión:
- mantiene una GUI minimalista;
- registra routers API y web;
- expone health check general;
- monta archivos estáticos;
- aplica middleware de cabeceras de seguridad;
- corrige automáticamente ejecuciones huérfanas en estado running.

Cambio de refactorización:
- Las utilidades compartidas viven en api/web_common.py.
- La ruta Inicio vive en api/routes_home.py.
- La ruta POST /scan vive en api/routes_web_scan.py.
- La ruta web de historial vive en api/routes_web_history.py.
- La ruta de detalle de ejecución vive en api/routes_execution_detail.py.
- Las rutas del Reporte General viven en api/routes_professional_report.py.
- Los filtros Jinja se registran desde api/web_common.py.

Cambio para KPIs / Grafana:
- Si una ejecución queda en estado running por más de 15 minutos,
  DASTXH la marca automáticamente como failed.
- Esto evita que el tablero muestre una diferencia confusa entre
  total de evaluaciones, finalizadas y fallidas.
"""

from __future__ import annotations

import os
import time
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
# CONFIGURACIÓN DE EJECUCIONES HUÉRFANAS
# ==========================================================
# DASTXH puede quedar con ejecuciones en estado "running"
# si hubo una interrupción del contenedor, cierre inesperado,
# error externo o una URL pública que dejó el flujo incompleto.
#
# Para no afectar KPIs ni historial, el backend marca como failed
# las ejecuciones running que superen el límite configurado.
#
# Se puede ajustar desde .env / docker-compose:
# DASTXH_STALE_RUNNING_MINUTES=15
# DASTXH_STALE_CLEANUP_INTERVAL_SECONDS=60

STALE_RUNNING_MINUTES_ENV = "DASTXH_STALE_RUNNING_MINUTES"
STALE_CLEANUP_INTERVAL_SECONDS_ENV = "DASTXH_STALE_CLEANUP_INTERVAL_SECONDS"

DEFAULT_STALE_RUNNING_MINUTES = 15
DEFAULT_STALE_CLEANUP_INTERVAL_SECONDS = 60

# Control interno para no ejecutar la limpieza en cada request.
_LAST_STALE_CLEANUP_MONOTONIC = 0.0


# ==========================================================
# APP FASTAPI
# ==========================================================

app = FastAPI(
    title="DASTXH Web",
    version="0.4.4",
    description=(
        "GUI web para DASTXH con flujo profundo controlado, "
        "reporte general versionado, exportación PDF, fechas locales "
        "y control de ejecuciones huérfanas"
    ),
)


# ==========================================================
# HELPERS INTERNOS: EJECUCIONES HUÉRFANAS
# ==========================================================

def get_stale_running_minutes() -> int:
    """
    Devuelve el límite de minutos permitido para una ejecución running.

    Si la variable de entorno no existe, no es numérica o es menor que 1,
    se usa el valor por defecto de 15 minutos.
    """
    raw_value = os.getenv(
        STALE_RUNNING_MINUTES_ENV,
        str(DEFAULT_STALE_RUNNING_MINUTES),
    )

    try:
        minutes = int(raw_value)
    except Exception:
        minutes = DEFAULT_STALE_RUNNING_MINUTES

    if minutes < 1:
        return DEFAULT_STALE_RUNNING_MINUTES

    return minutes


def get_stale_cleanup_interval_seconds() -> int:
    """
    Devuelve cada cuántos segundos puede ejecutarse la limpieza automática.

    Esto evita consultar y actualizar la base de datos en cada request.
    """
    raw_value = os.getenv(
        STALE_CLEANUP_INTERVAL_SECONDS_ENV,
        str(DEFAULT_STALE_CLEANUP_INTERVAL_SECONDS),
    )

    try:
        seconds = int(raw_value)
    except Exception:
        seconds = DEFAULT_STALE_CLEANUP_INTERVAL_SECONDS

    if seconds < 1:
        return DEFAULT_STALE_CLEANUP_INTERVAL_SECONDS

    return seconds


def should_run_stale_cleanup_for_path(path: str) -> bool:
    """
    Determina si una ruta debe disparar la limpieza de ejecuciones huérfanas.

    Se evita ejecutar esta lógica para archivos estáticos o rutas de salud.
    """
    if not path:
        return False

    if path.startswith("/static"):
        return False

    if path == "/health":
        return False

    # Rutas principales donde interesa que el estado ya esté corregido:
    # - página de inicio
    # - historial
    # - detalle de ejecución
    # - inicio de escaneo
    # - endpoints API de historial/reportes si son consultados
    return (
        path == "/"
        or path.startswith("/history")
        or path.startswith("/executions")
        or path.startswith("/scan")
        or path.startswith("/api/history")
        or path.startswith("/api/reports")
    )


def cleanup_stale_running_executions(force: bool = False) -> int:
    """
    Cierra automáticamente ejecuciones running antiguas.

    Si force=True:
    - ejecuta la limpieza sin respetar el intervalo interno.

    Si force=False:
    - solo ejecuta si ya pasó el intervalo configurado.

    Retorna:
    - cantidad de ejecuciones corregidas.
    """
    global _LAST_STALE_CLEANUP_MONOTONIC

    now_monotonic = time.monotonic()
    interval_seconds = get_stale_cleanup_interval_seconds()

    if not force:
        elapsed = now_monotonic - _LAST_STALE_CLEANUP_MONOTONIC

        if elapsed < interval_seconds:
            return 0

    dsn = get_dsn()
    stale_minutes = get_stale_running_minutes()

    updated_count = db_layer.mark_stale_running_executions_as_failed(
        dsn=dsn,
        max_age_minutes=stale_minutes,
        error_message=(
            f"La evaluación quedó en estado running por más de {stale_minutes} minutos. "
            "DASTXH la marcó automáticamente como fallida para evitar una ejecución huérfana."
        ),
    )

    _LAST_STALE_CLEANUP_MONOTONIC = now_monotonic

    return updated_count


# ==========================================================
# MIDDLEWARES
# ==========================================================

@app.middleware("http")
async def cleanup_stale_running_middleware(request: Request, call_next):
    """
    Middleware ligero para corregir ejecuciones huérfanas.

    No se ejecuta para cada archivo estático ni en cada request.
    Usa un intervalo interno para evitar carga innecesaria sobre PostgreSQL.
    """
    if should_run_stale_cleanup_for_path(request.url.path):
        try:
            cleanup_stale_running_executions(force=False)
        except Exception:
            # La limpieza no debe bloquear la navegación.
            # Si falla, el sistema puede seguir funcionando y se intentará
            # nuevamente en la siguiente ventana de limpieza.
            pass

    response = await call_next(request)
    return response


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
# EVENTO DE ARRANQUE
# ==========================================================

@app.on_event("startup")
def startup_cleanup_stale_running_executions() -> None:
    """
    Limpieza automática al iniciar el orquestador.

    Si el contenedor se apagó durante una evaluación, al levantarlo de nuevo
    se corrigen ejecuciones running antiguas antes de consultar historial,
    inicio o Grafana.
    """
    try:
        cleanup_stale_running_executions(force=True)
    except Exception:
        # No detenemos el arranque de FastAPI por un problema de limpieza.
        # Las rutas web volverán a intentarlo posteriormente.
        pass


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

    Nota:
    - Esta ruta no ejecuta la limpieza automática directamente.
    - Solo reporta la configuración activa.
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
        "stale_running_minutes": get_stale_running_minutes(),
        "stale_cleanup_interval_seconds": get_stale_cleanup_interval_seconds(),
        "professional_report_enabled": True,
        "professional_report_pdf_enabled": True,
        "professional_report_version_pdf_enabled": True,
    }