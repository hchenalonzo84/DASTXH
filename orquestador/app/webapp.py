"""
webapp.py
- Aplicación web principal de DASTXH usando FastAPI.
- Esta versión queda ajustada para trabajar mejor con el nuevo flujo:
  * la GUI web ya no ejecuta el escaneo de forma síncrona
  * el escaneo se lanza en segundo plano
  * la petición POST responde rápido y redirige al detalle
  * el detalle puede consultarse aunque la ejecución siga en curso

Esta versión además agrega:
- selección de scan_profile desde la GUI
- modo de hsecscan:
    * auto    -> lo resuelve el backend según perfil
    * enable  -> fuerza True
    * disable -> fuerza False
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
from services.scanner_service import start_scan_in_background
from utils import ensure_dir, wait_for_db


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
    version="0.2.0",
    description="GUI web inicial para DASTXH",
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


def validate_scan_profile(value: str) -> str:
    """
    Valida el perfil elegido desde la GUI.
    """
    scan_profile = (value or "").strip().lower()

    if scan_profile not in {"superficial", "profundo"}:
        raise HTTPException(
            status_code=400,
            detail="scan_profile debe ser 'superficial' o 'profundo'.",
        )

    return scan_profile


def parse_hsecscan_mode(value: str) -> Optional[bool]:
    """
    Convierte el modo del formulario a un valor compatible
    con scanner_service.

    Mapeo:
    - auto    -> None
    - enable  -> True
    - disable -> False
    """
    mode = (value or "auto").strip().lower()

    if mode == "auto":
        return None
    if mode == "enable":
        return True
    if mode == "disable":
        return False

    raise HTTPException(
        status_code=400,
        detail="hsecscan_mode debe ser 'auto', 'enable' o 'disable'.",
    )


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
# ==========================================================
# RUTAS WEB
# ==========================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Página principal.

    Muestra:
    - formulario para iniciar una evaluación
    - últimas ejecuciones registradas
    """
    recent_executions = load_recent_executions(limit=10)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "DASTXH - Inicio",
            "default_timeout": get_default_timeout(),
            "default_scan_profile": "superficial",
            "default_hsecscan_mode": "auto",
            "recent_executions": recent_executions,
        },
    )


@app.post("/scan")
def start_scan(
    url: str = Form(...),
    timeout: Optional[int] = Form(default=None),
    scan_profile: str = Form(default="superficial"),
    hsecscan_mode: str = Form(default="auto"),
):
    """
    Inicia un escaneo desde la GUI web.

    Ahora acepta:
    - scan_profile
    - hsecscan_mode (auto/enable/disable)
    """
    # ------------------------------------------------------
    # Validar entrada desde formulario
    # ------------------------------------------------------
    target_url = validate_target_url(url)
    timeout_s = timeout if timeout is not None else get_default_timeout()
    validated_scan_profile = validate_scan_profile(scan_profile)
    enable_hsecscan = parse_hsecscan_mode(hsecscan_mode)

    # ------------------------------------------------------
    # Preparar entorno y esperar base de datos
    # ------------------------------------------------------
    ensure_work_paths()
    dsn = wait_until_db_ready(timeout_s=20)

    # ------------------------------------------------------
    # Lanzar escaneo en background
    # ------------------------------------------------------
    result = start_scan_in_background(
        dsn=dsn,
        workdir=WORKDIR,
        url=target_url,
        timeout_s=timeout_s,
        request_source="web",
        scan_profile=validated_scan_profile,
        enable_hsecscan=enable_hsecscan,
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
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

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