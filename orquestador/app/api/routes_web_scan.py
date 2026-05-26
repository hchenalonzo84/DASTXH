"""
routes_web_scan.py
- Ruta web para iniciar evaluaciones DASTXH desde la GUI.

Objetivo:
- Sacar de webapp.py la ruta:
      POST /scan
- Mantener la misma URL pública.
- Mantener el flujo profundo controlado desde interfaz web.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from api.web_common import (
    WORKDIR,
    ensure_work_paths,
    get_default_timeout,
    get_standard_hsecscan_enabled,
    get_standard_scan_profile,
    validate_target_url,
    wait_until_db_ready,
)
from services.scanner_service import start_scan_in_background


# ==========================================================
# ROUTER
# ==========================================================

router = APIRouter(tags=["web-scan"])


# ==========================================================
# POST: INICIAR EVALUACIÓN DESDE GUI
# ==========================================================

@router.post("/scan")
def start_scan(
    request: Request,
    url: str = Form(...),
    timeout: Optional[int] = Form(default=None),
):
    """
    Inicia una evaluación desde la GUI web.

    Regla actual:
    - el usuario solo ingresa URL y timeout base;
    - DASTXH ejecuta internamente el flujo profundo controlado;
    - hsecscan queda habilitado como parte del flujo estándar.

    Nota:
    - request_source se conserva con valor "web" en BD por compatibilidad.
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
        raise HTTPException(
            status_code=500,
            detail="No se obtuvo execution_id.",
        )

    return RedirectResponse(
        url=f"/executions/{execution_id}",
        status_code=303,
    )