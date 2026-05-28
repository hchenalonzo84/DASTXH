"""
routes_home.py
- Ruta web de inicio de DASTXH.

Objetivo:
- Sacar de webapp.py la ruta:
      GET /
- Mantener la misma URL pública.
- Mantener el mismo template:
      index.html
- Enviar a la vista el catálogo de laboratorios disponibles.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from api.lab_targets import get_lab_targets
from api.web_common import (
    get_default_timeout,
    load_recent_executions,
    templates,
)


# ==========================================================
# ROUTER
# ==========================================================

router = APIRouter(tags=["web-home"])


# ==========================================================
# GET: INICIO
# ==========================================================

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Página principal de DASTXH.

    Muestra:
    - formulario para iniciar evaluación;
    - ejecuciones recientes;
    - timeout por defecto configurado;
    - catálogo de laboratorios para el menú superior.
    """
    recent_executions = load_recent_executions(limit=10)
    lab_targets = get_lab_targets()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "DASTXH - Inicio",
            "default_timeout": get_default_timeout(),
            "recent_executions": recent_executions,
            "lab_targets": lab_targets,
        },
    )