"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.
- Esta versión ya se conecta con:
  * la base de datos
  * el servicio de escaneo reutilizable
  * el historial real de ejecuciones
  * el detalle real por ejecución

Objetivos de esta etapa:
- exponer una GUI web inicial
- permitir iniciar escaneos desde la web
- consultar historial desde PostgreSQL
- ver detalle por ejecución
- seguir reutilizando la misma lógica que usa la CLI

Importante:
- Se intenta mantener compatibilidad básica con los templates
  iniciales que ya fueron creados.
- Más adelante podremos mejorar los templates para mostrar
  más información visual.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import db as db_layer
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.routes_history import router as history_router
from api.routes_reports import router as reports_router
from api.routes_scans import router as scans_router
from services.scanner_service import execute_scan
from utils import ensure_dir, wait_for_db


# ==========================================================
# RUTAS BASE DEL PROYECTO
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "web" / "templates"
STATIC_DIR = BASE_DIR / "web" / "static"

# Directorio lógico de trabajo dentro del contenedor
WORKDIR = Path(os.getenv("WORKDIR", "/work"))
REPORTS_DIR = WORKDIR / "reports"


# ==========================================================
# APP FASTAPI
# ==========================================================

app = FastAPI(
    title="DASTXH Web",
    version="0.2.0",
    description="GUI web inicial para DASTXH",
)
# Middleware para agregar cabeceras de seguridad a todas las respuestas
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    # Cabeceras seguras y conservadoras
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    return response

# Archivos estáticos (CSS, JS, etc.)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Motor de templates Jinja2
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Routers auxiliares de la API
app.include_router(scans_router)
app.include_router(history_router)
app.include_router(reports_router)


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def get_dsn() -> str:
    """
    Obtiene la cadena de conexión desde DATABASE_URL.
    Lanza excepción si no existe.
    """
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL no está configurada.")
    return dsn


def get_default_timeout() -> int:
    """
    Obtiene el timeout por defecto para escaneos web.
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
    Extrae el nombre de la carpeta final desde una ruta lógica
    como /work/reports/20260313_101010

    Si no se puede determinar, devuelve cadena vacía.
    """
    if not report_dir:
        return ""
    return Path(report_dir).name


def load_recent_executions(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Carga ejecuciones recientes desde la vista de resumen.
    Si falla la BD, devuelve lista vacía.
    """
    try:
        dsn = get_dsn()
        wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=10)
        return db_layer.list_execution_summaries(dsn=dsn, limit=limit, offset=0)
    except Exception:
        return []


# ==========================================================
# RUTAS WEB
# ==========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Página principal.
    Muestra:
    - formulario básico para iniciar escaneo
    - ejecuciones recientes
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
    timeout: int = Form(default=get_default_timeout()),
):
    """
    Inicia un escaneo desde la GUI web.

    En esta versión inicial:
    - la ejecución se hace de forma síncrona
    - cuando termina, redirige al detalle de la ejecución

    Más adelante se puede convertir a ejecución en segundo plano.
    """
    target_url = (url or "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="La URL no puede estar vacía.")

    dsn = get_dsn()
    ensure_work_paths()
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=20)

    result = execute_scan(
        dsn=dsn,
        workdir=WORKDIR,
        url=target_url,
        timeout_s=timeout,
        request_source="web",
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

    Para mantener compatibilidad básica con el template actual:
    - se envía 'runs' como lista de ids
    - también se envía 'executions' con el detalle completo
    """
    dsn = get_dsn()
    ensure_work_paths()
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=20)

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

    Carga:
    - resumen y detalle desde la base de datos
    - lista de artifacts
    - nombre de carpeta real del reporte

    Para mantener compatibilidad con el template actual:
    - se envía run_id como el nombre de la carpeta física
    - se envía files como lista simple de nombres
    """
    dsn = get_dsn()
    ensure_work_paths()
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=20)

    detail = db_layer.get_execution_detail(dsn=dsn, execution_id=execution_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Ejecución no encontrada.")

    artifacts = detail.get("artifacts", [])
    files = [str(item.get("file_name", "")) for item in artifacts if item.get("file_name")]
    run_id = get_report_folder_name(detail.get("report_dir"))

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
    }