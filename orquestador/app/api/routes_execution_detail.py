"""
routes_execution_detail.py
- Ruta web para consultar el detalle de una ejecución DASTXH.

Objetivo:
- Sacar de webapp.py la ruta:
      GET /executions/{execution_id}
- Mantener el mismo comportamiento visual y funcional.
- Preparar el contexto de:
    * Resumen
    * Detalle técnico
    * Archivos generados
    * Reporte general
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from api.web_common import (
    ensure_work_paths,
    get_report_folder_name,
    load_execution_detail_or_404,
    templates,
    wait_until_db_ready,
)
from services.professional_report_service import build_professional_report_view_context


# ==========================================================
# ROUTER
# ==========================================================

router = APIRouter(tags=["execution-detail"])


# ==========================================================
# GET: DETALLE DE EJECUCIÓN
# ==========================================================

@router.get("/executions/{execution_id}", response_class=HTMLResponse)
def execution_detail(request: Request, execution_id: int):
    """
    Página de detalle de una ejecución.

    Esta vista concentra:
    - Resumen consolidado.
    - Detalle técnico en crudo.
    - Archivos generados.
    - Reporte general profesional.

    Nota:
    - La ruta pública se mantiene igual:
          /executions/{execution_id}
    - Solo se movió desde webapp.py hacia este router.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(
        dsn=dsn,
        execution_id=execution_id,
    )

    artifacts: List[Dict[str, Any]] = detail.get("artifacts", [])
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