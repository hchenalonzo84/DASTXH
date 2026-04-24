"""
routes_scans.py
- Endpoints API para iniciar y consultar escaneos DASTXH.

Esta versión:
- permite iniciar un escaneo vía POST sin bloquear la respuesta HTTP
- devuelve un execution_id inmediatamente
- permite elegir solo el perfil de análisis
- resuelve internamente el uso de hsecscan según el perfil
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import db as db_layer
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.scanner_service import start_scan_in_background
from utils import ensure_dir, wait_for_db


# ==========================================================
# ROUTER PRINCIPAL
# ==========================================================

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ==========================================================
# MODELOS DE ENTRADA / SALIDA
# ==========================================================

class ScanCreateRequest(BaseModel):
    """
    Modelo del cuerpo JSON esperado para iniciar un escaneo.
    """
    url: str = Field(..., description="URL objetivo a evaluar.")
    timeout: Optional[int] = Field(
        default=None,
        ge=1,
        description="Timeout opcional en segundos para el escaneo.",
    )
    scan_profile: str = Field(
        default="superficial",
        description="Perfil de análisis: superficial o profundo.",
    )


class ScanCreateResponse(BaseModel):
    """
    Respuesta mínima que devolvemos cuando el backend acepta
    un escaneo para ejecutarlo en segundo plano.
    """
    ok: bool
    accepted: bool
    execution_id: int
    status: str
    target_url: str
    request_source: str
    scan_profile: str
    report_dir: str


# ==========================================================
# HELPERS INTERNOS DEL MÓDULO
# ==========================================================

def get_dsn() -> str:
    """
    Obtiene la cadena de conexión a PostgreSQL desde DATABASE_URL.
    """
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL no está configurada.")
    return dsn


def get_default_timeout() -> int:
    """
    Lee el timeout por defecto desde el entorno.
    """
    return int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30"))


def get_workdir() -> Path:
    """
    Devuelve el directorio lógico base de trabajo del contenedor.
    """
    return Path(os.getenv("WORKDIR", "/work"))


def ensure_work_paths() -> None:
    """
    Garantiza que exista la estructura base de trabajo.
    """
    workdir = get_workdir()
    ensure_dir(workdir)
    ensure_dir(workdir / "reports")


def validate_target_url(value: str) -> str:
    """
    Limpia y valida la URL objetivo.
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
    Valida el perfil de análisis.
    """
    profile = (value or "").strip().lower()

    if profile not in ("superficial", "profundo"):
        raise HTTPException(
            status_code=400,
            detail="El perfil de análisis debe ser superficial o profundo.",
        )

    return profile


def wait_until_db_ready(timeout_s: int = 20) -> str:
    """
    Espera a que la base de datos esté disponible y devuelve el DSN.
    """
    dsn = get_dsn()
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=timeout_s)
    return dsn


# ==========================================================
# ENDPOINT DE SALUD
# ==========================================================

@router.get("/health")
def scans_health() -> Dict[str, Any]:
    """
    Endpoint simple de salud del módulo de escaneos.
    """
    db_ok = False

    try:
        dsn = get_dsn()
        db_layer.ping_db(dsn)
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "module": "scans",
        "ok": True,
        "db_ok": db_ok,
    }


# ==========================================================
# POST: INICIAR ESCANEO EN BACKGROUND
# ==========================================================

@router.post("", response_model=ScanCreateResponse)
def create_scan(payload: ScanCreateRequest) -> Dict[str, Any]:
    """
    Inicia un escaneo en segundo plano y devuelve inmediatamente
    el execution_id.
    """
    target_url = validate_target_url(payload.url)
    resolved_scan_profile = validate_scan_profile(payload.scan_profile)
    timeout_s = payload.timeout if payload.timeout is not None else get_default_timeout()

    ensure_work_paths()
    dsn = wait_until_db_ready(timeout_s=20)

    result = start_scan_in_background(
        dsn=dsn,
        workdir=get_workdir(),
        url=target_url,
        timeout_s=timeout_s,
        request_source="api",
        scan_profile=resolved_scan_profile,
        enable_hsecscan=None,
    )

    execution_id = result.get("execution_id")
    if execution_id is None:
        raise HTTPException(
            status_code=500,
            detail="No fue posible obtener el execution_id del escaneo iniciado.",
        )

    return result


# ==========================================================
# GET: RESUMEN DE UNA EJECUCIÓN
# ==========================================================

@router.get("/{execution_id}")
def get_scan_summary(execution_id: int) -> Dict[str, Any]:
    """
    Devuelve el resumen actual de una ejecución.
    """
    if execution_id <= 0:
        raise HTTPException(status_code=400, detail="execution_id inválido.")

    dsn = wait_until_db_ready(timeout_s=20)

    summary = db_layer.get_execution_summary(
        dsn=dsn,
        execution_id=execution_id,
    )

    if not summary:
        raise HTTPException(status_code=404, detail="Ejecución no encontrada.")

    return {
        "ok": True,
        "execution": summary,
    }


# ==========================================================
# GET: DETALLE COMPLETO DE UNA EJECUCIÓN
# ==========================================================

@router.get("/{execution_id}/detail")
def get_scan_detail(execution_id: int) -> Dict[str, Any]:
    """
    Devuelve el detalle completo de una ejecución.
    """
    if execution_id <= 0:
        raise HTTPException(status_code=400, detail="execution_id inválido.")

    dsn = wait_until_db_ready(timeout_s=20)

    detail = db_layer.get_execution_detail(
        dsn=dsn,
        execution_id=execution_id,
    )

    if not detail:
        raise HTTPException(status_code=404, detail="Ejecución no encontrada.")

    return {
        "ok": True,
        "execution": detail,
    }