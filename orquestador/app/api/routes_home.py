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

Mejora actual:
- Enriquece ejecuciones recientes con campos visuales de URL.
- Envía lab_targets para que base.html agregue el menú superior de Laboratorios.
- El enlace de Grafana se calcula en el navegador desde topbar_extra_links.html.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from api.lab_targets import get_lab_targets
from api.target_display_utils import enrich_execution_rows_with_target_url_display
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
    - menú superior con Laboratorios y Grafana.
    """
    recent_executions = load_recent_executions(limit=10)
    recent_executions = enrich_execution_rows_with_target_url_display(
        recent_executions
    )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "DASTXH - Inicio",
            "default_timeout": get_default_timeout(),
            "recent_executions": recent_executions,
            "lab_targets": get_lab_targets(),
        },
    )