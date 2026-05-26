"""
routes_web_history.py
- Ruta web para consultar el historial de ejecuciones DASTXH.

Objetivo:
- Sacar de webapp.py la ruta:
      GET /history
- Mantener la misma URL pública.
- Mantener el mismo template:
      history.html
"""

from __future__ import annotations

from typing import Any, Dict, List

import db as db_layer
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from api.web_common import (
    ensure_work_paths,
    templates,
    wait_until_db_ready,
)


# ==========================================================
# ROUTER
# ==========================================================

router = APIRouter(tags=["web-history"])


# ==========================================================
# GET: HISTORIAL WEB
# ==========================================================

@router.get("/history", response_class=HTMLResponse)
def history_page(request: Request):
    """
    Página de historial de ejecuciones.

    Esta ruta muestra las ejecuciones registradas en PostgreSQL
    para que el usuario pueda consultar resultados anteriores.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    executions: List[Dict[str, Any]] = db_layer.list_execution_summaries(
        dsn=dsn,
        limit=100,
        offset=0,
    )

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