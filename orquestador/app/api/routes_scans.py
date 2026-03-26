"""
routes_scans.py
- Endpoints API para iniciar y consultar escaneos DASTXH.

Objetivo de esta versión:
- permitir iniciar un escaneo vía POST sin bloquear la respuesta HTTP
- devolver un execution_id inmediatamente
- consultar después el estado/resumen de la ejecución con GET
- consultar el detalle completo cuando sea necesario

Esto es clave para desacoplar:
- la navegación de la GUI
- del tiempo real que dura el pipeline del escaneo
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

    Ejemplo:
    {
      "url": "https://example.com",
      "timeout": 30
    }

    Notas:
    - url es obligatoria
    - timeout es opcional; si no llega, se usa el valor por defecto
      del entorno
    """
    url: str = Field(..., description="URL objetivo a evaluar.")
    timeout: Optional[int] = Field(
        default=None,
        ge=1,
        description="Timeout opcional en segundos para el escaneo.",
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
    report_dir: str


# ==========================================================
# HELPERS INTERNOS DEL MÓDULO
# ==========================================================

def get_dsn() -> str:
    """
    Obtiene la cadena de conexión a PostgreSQL desde la variable
    de entorno DATABASE_URL.

    Lanza excepción si no está configurada.
    """
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL no está configurada.")
    return dsn


def get_default_timeout() -> int:
    """
    Lee el timeout por defecto desde el entorno.

    Si no existe, usa 30 segundos.
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

    De momento solo necesitamos asegurar /work y /work/reports.
    """
    workdir = get_workdir()
    ensure_dir(workdir)
    ensure_dir(workdir / "reports")


def validate_target_url(value: str) -> str:
    """
    Limpia y valida la URL objetivo.

    Validaciones mínimas:
    - no vacía
    - debe comenzar con http:// o https://

    Nota:
    dejamos la validación deliberadamente simple para no bloquear
    casos legítimos de laboratorio que una validación más estricta
    podría rechazar.
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


def wait_until_db_ready(timeout_s: int = 20) -> str:
    """
    Espera a que la base de datos esté disponible y devuelve el DSN.

    Esto evita que el endpoint intente crear una ejecución cuando
    PostgreSQL todavía no está listo.
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

    Además de devolver "ok", intenta comprobar la conectividad
    con PostgreSQL para tener una señal más útil desde fuera.
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

    Este endpoint es la base del nuevo flujo correcto para la GUI:

    1) la GUI hace POST /api/scans
    2) recibe execution_id rápido
    3) redirige o consulta luego GET /api/scans/{id}
    4) el pipeline sigue corriendo en background

    Con esto evitamos que el navegador dependa de esperar
    el proceso completo del escaneo.
    """
    # ------------------------------------------------------
    # Validar entrada
    # ------------------------------------------------------
    target_url = validate_target_url(payload.url)

    # Si no enviaron timeout, usamos el configurado por defecto
    timeout_s = payload.timeout if payload.timeout is not None else get_default_timeout()

    # ------------------------------------------------------
    # Preparar entorno y BD
    # ------------------------------------------------------
    ensure_work_paths()
    dsn = wait_until_db_ready(timeout_s=20)

    # ------------------------------------------------------
    # Lanzar el escaneo en background
    # ------------------------------------------------------
    result = start_scan_in_background(
        dsn=dsn,
        workdir=get_workdir(),
        url=target_url,
        timeout_s=timeout_s,
        request_source="api",
    )

    # Validación defensiva por si en el futuro cambia el servicio
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

    Esta vista compacta es útil para:
    - polling ligero desde la GUI
    - mostrar estado actual del escaneo
    - saber si ya terminó o falló sin pedir todo el detalle
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

    Incluye:
    - datos base de la ejecución
    - resultados de headers
    - resultados de hsecscan
    - resultados de Dalfox
    - artifacts asociados

    Este endpoint será útil para:
    - la pantalla de detalle de la GUI
    - futuras integraciones
    - pruebas manuales con Postman/Insomnia
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