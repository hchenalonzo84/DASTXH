"""
routes_professional_report.py
- Rutas web del Reporte General profesional de DASTXH.

Objetivo:
- Sacar de webapp.py la lógica de:
    * generación asistida por IA;
    * guardado editable;
    * impresión PDF;
    * impresión de versiones históricas;
    * consulta de versiones históricas.

Regla:
- Este router conserva las mismas URLs públicas que antes.
- No cambia el comportamiento visible de la GUI.
"""

from __future__ import annotations

from typing import Any, Dict

import config
import db as db_layer
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from api.web_common import (
    build_report_payload_from_form,
    ensure_work_paths,
    get_report_folder_name,
    load_execution_detail_or_404,
    load_professional_report_version_or_404,
    redirect_to_execution_report_tab,
    redirect_to_generated_pdf,
    register_professional_report_pdf_from_version,
    templates,
    wait_until_db_ready,
)
from services.ai_report_service import generate_professional_report_with_ai
from services.professional_report_service import build_professional_report_view_context


# ==========================================================
# ROUTER
# ==========================================================

router = APIRouter(tags=["professional-report"])


# ==========================================================
# POST: GENERAR REPORTE CON IA
# ==========================================================

@router.post("/executions/{execution_id}/professional-report/generate")
def generate_professional_report(request: Request, execution_id: int):
    """
    Genera o reemplaza el borrador actual del reporte general usando IA.

    Comportamiento:
    - Toma datos técnicos ya persistidos.
    - Solicita redacción asistida por IA.
    - Si la IA falla, usa fallback determinístico.
    - Guarda el contenido como versión actual editable.
    - Crea una versión histórica.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    generation_result = generate_professional_report_with_ai(detail)
    payload = generation_result.get("payload") or {}

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=500,
            detail="No fue posible generar el contenido del reporte general.",
        )

    used_ai = bool(generation_result.get("used_ai"))
    model_name = generation_result.get("model_name")

    if used_ai:
        change_reason = "Borrador generado con asistencia de IA para reporte general."
        change_type = getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_AI_GENERATED",
            "ai_generated",
        )
    else:
        error_text = generation_result.get("error")
        change_reason = (
            "Borrador generado con plantilla determinística porque la IA no se usó "
            "o no respondió correctamente."
        )

        if error_text:
            change_reason = f"{change_reason} Detalle: {error_text}"

        change_type = getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE",
            "manual_save",
        )

    db_layer.save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=used_ai,
        ai_model_name=model_name if used_ai else None,
        change_type=change_type,
        change_reason=change_reason,
        updated_by="web",
    )

    return redirect_to_execution_report_tab(execution_id)


# ==========================================================
# POST: GUARDAR REPORTE EDITABLE
# ==========================================================

@router.post("/executions/{execution_id}/professional-report/save")
async def save_professional_report(request: Request, execution_id: int):
    """
    Guarda cambios manuales del formulario editable.

    Cada guardado:
    - Actualiza professional_reports.
    - Crea una nueva fila en professional_report_versions.
    - Deja versiones anteriores como solo lectura.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    form = await request.form()
    form_data = dict(form)

    payload = build_report_payload_from_form(form_data)

    db_layer.save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=False,
        ai_model_name=None,
        change_type=getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE",
            "manual_save",
        ),
        change_reason="Cambios guardados manualmente desde la pestaña Reporte general.",
        updated_by="web",
    )

    return redirect_to_execution_report_tab(execution_id)


# ==========================================================
# POST: IMPRIMIR REPORTE ACTUAL
# ==========================================================

@router.post("/executions/{execution_id}/professional-report/print")
async def print_professional_report(request: Request, execution_id: int):
    """
    Imprime/exporta el Reporte General a PDF desde el formulario actual.

    Esta ruta se conserva por compatibilidad.

    En la GUI nueva, lo recomendable es:
    - Guardar primero.
    - Luego imprimir una versión histórica ya guardada.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    form = await request.form()
    form_data = dict(form)
    payload = build_report_payload_from_form(form_data)

    pdf_version = db_layer.create_professional_report_pdf_snapshot_version(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        change_reason="Versión histórica creada automáticamente para impresión/exportación PDF.",
        created_by="web",
    )

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    pdf_result = register_professional_report_pdf_from_version(
        dsn=dsn,
        execution_id=execution_id,
        detail=detail,
        version=pdf_version,
        exported_by="web",
    )

    return redirect_to_generated_pdf(
        run_id=str(pdf_result.get("run_id") or ""),
        pdf_file_name=str(pdf_result.get("pdf_file_name") or ""),
    )


# ==========================================================
# POST: IMPRIMIR VERSIÓN HISTÓRICA
# ==========================================================

@router.post("/executions/{execution_id}/professional-report/versions/{version_id}/print")
def print_professional_report_version(
    request: Request,
    execution_id: int,
    version_id: int,
):
    """
    Imprime/exporta una versión histórica específica del Reporte General.

    Ventajas:
    - No modifica el contenido actual editable.
    - No crea una versión nueva innecesaria.
    - Permite imprimir versiones antiguas.
    - Mantiene trazabilidad: PDF -> versión histórica exacta.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    version = load_professional_report_version_or_404(
        dsn=dsn,
        execution_id=execution_id,
        version_id=version_id,
    )

    pdf_result = register_professional_report_pdf_from_version(
        dsn=dsn,
        execution_id=execution_id,
        detail=detail,
        version=version,
        exported_by="web",
    )

    return redirect_to_generated_pdf(
        run_id=str(pdf_result.get("run_id") or ""),
        pdf_file_name=str(pdf_result.get("pdf_file_name") or ""),
    )


# ==========================================================
# GET: CONSULTAR VERSIÓN HISTÓRICA
# ==========================================================

@router.get(
    "/executions/{execution_id}/professional-report/versions/{version_id}",
    response_class=HTMLResponse,
)
def view_professional_report_version(
    request: Request,
    execution_id: int,
    version_id: int,
):
    """
    Consulta una versión histórica del reporte general.

    Regla:
    - Las versiones históricas son solo lectura.
    - No existe ruta POST para editarlas.
    - La versión histórica consultada también puede imprimirse desde la GUI.
    """
    dsn = wait_until_db_ready(timeout_s=20)
    ensure_work_paths()

    detail = load_execution_detail_or_404(dsn=dsn, execution_id=execution_id)

    version = load_professional_report_version_or_404(
        dsn=dsn,
        execution_id=execution_id,
        version_id=version_id,
    )

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
            "title": f"DASTXH - Versión histórica {version.get('version_number')}",
            "execution_id": execution_id,
            "run_id": run_id,
            "files": files,
            "detail": detail,
            "artifacts": artifacts,
            "professional_report_view": professional_report_view,
            "readonly_report_version": version,
        },
    )


# ==========================================================
# GET: SALUD DEL MÓDULO
# ==========================================================

@router.get("/api/professional-report/health")
def professional_report_health() -> Dict[str, Any]:
    """
    Endpoint simple de salud del módulo Reporte General.
    """
    return {
        "module": "professional-report",
        "ok": True,
    }