"""
execution_repository.py
- Repositorio de ejecuciones de DASTXH.

Responsabilidad:
- Crear nuevas ejecuciones.
- Actualizar estados de ejecución.
- Consultar resumen/historial.
- Cerrar automáticamente ejecuciones huérfanas que quedaron en running.

Importante:
- Este archivo NO ejecuta herramientas externas.
- Este archivo NO genera reportes.
- Este archivo solo administra la persistencia principal de executions.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

from repositories.db_connection import connect
from utils import utc_now


# ==========================================================
# CREACIÓN DE EJECUCIONES
# ==========================================================

def insert_execution(
    dsn: str,
    target_url: str,
    request_source: str = "cli",
    report_dir: Optional[str] = None,
    status: str = "initiated",
    scan_profile: str = "superficial",
    enable_hsecscan: bool = False,
    urls_ingresadas: int = 1,
    urls_evaluadas: int = 0,
) -> int:
    """
    Inserta una nueva ejecución y devuelve el ID generado.

    Observación:
    - started_at se asigna desde el backend para que siempre exista
      una referencia temporal aunque la ejecución falle después.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO executions (
                    target_url,
                    started_at,
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    target_url,
                    utc_now(),
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                ),
            )
            row = cur.fetchone()

        conn.commit()

    if not row or "id" not in row:
        raise RuntimeError("No fue posible obtener el id de la ejecución insertada.")

    return int(row["id"])


# ==========================================================
# ACTUALIZACIÓN DE ESTADO
# ==========================================================

def update_execution_status(
    dsn: str,
    execution_id: int,
    status: str,
    error_message: Optional[str] = None,
    urls_evaluadas: Optional[int] = None,
    finished: bool = False,
) -> None:
    """
    Actualiza el estado general de una ejecución.

    Parámetros:
    - status: estado nuevo de la ejecución.
    - error_message: mensaje de error o explicación técnica.
    - urls_evaluadas: cantidad de URLs procesadas cuando aplica.
    - finished: si es True, asigna finished_at con la hora actual.
    """
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            if urls_evaluadas is None:
                cur.execute(
                    """
                    UPDATE executions
                    SET status = %s,
                        error_message = %s,
                        finished_at = CASE WHEN %s THEN %s ELSE finished_at END
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        finished,
                        now,
                        execution_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE executions
                    SET status = %s,
                        error_message = %s,
                        urls_evaluadas = %s,
                        finished_at = CASE WHEN %s THEN %s ELSE finished_at END
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        urls_evaluadas,
                        finished,
                        now,
                        execution_id,
                    ),
                )

        conn.commit()


def update_execution_running(
    dsn: str,
    execution_id: int,
) -> None:
    """
    Marca una ejecución como running.

    Se usa cuando el flujo de evaluación ya fue tomado por el motor
    y se encuentra en proceso.
    """
    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status="running",
        error_message=None,
        urls_evaluadas=0,
        finished=False,
    )


def update_execution_finished(
    dsn: str,
    execution_id: int,
    ok: bool,
    error_message: Optional[str] = None,
    urls_evaluadas: Optional[int] = None,
) -> None:
    """
    Marca la ejecución como finalizada o fallida.

    Si ok=True:
    - status = finished

    Si ok=False:
    - status = failed
    - error_message conserva la causa.
    """
    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status="finished" if ok else "failed",
        error_message=error_message,
        urls_evaluadas=urls_evaluadas,
        finished=True,
    )


# ==========================================================
# CIERRE AUTOMÁTICO DE EJECUCIONES HUÉRFANAS
# ==========================================================

def mark_stale_running_executions_as_failed(
    dsn: str,
    max_age_minutes: int = 15,
    error_message: Optional[str] = None,
) -> int:
    """
    Marca como failed las ejecuciones que quedaron en running demasiado tiempo.

    Problema que resuelve:
    - Si el contenedor se detiene, el navegador se cierra, una URL pública no responde,
      o ocurre una interrupción inesperada, una ejecución puede quedar como running.
    - Eso afecta historial, dashboard de Grafana y porcentaje de evaluaciones exitosas.

    Regla:
    - status = 'running'
    - started_at anterior al umbral definido
    - finished_at aún vacío

    Retorna:
    - cantidad de ejecuciones corregidas.
    """
    safe_minutes = int(max_age_minutes or 16)

    if safe_minutes < 1:
        safe_minutes = 16

    now = utc_now()
    stale_threshold = now - timedelta(minutes=safe_minutes)

    message = (
        error_message
        or (
            f"La evaluación permaneció en estado running por más de "
            f"{safe_minutes} minutos y fue cerrada automáticamente por DASTXH."
        )
    )

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE executions
                SET status = 'failed',
                    error_message = %s,
                    finished_at = %s
                WHERE status = 'running'
                  AND started_at IS NOT NULL
                  AND started_at < %s
                  AND finished_at IS NULL;
                """,
                (
                    message,
                    now,
                    stale_threshold,
                ),
            )

            updated_count = int(cur.rowcount or 0)

        conn.commit()

    return updated_count


# ==========================================================
# CONSULTAS DE HISTORIAL / RESUMEN
# ==========================================================

def get_execution_summary(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene una ejecución resumida por ID.

    Usa vw_execution_summary porque esta vista ya consolida:
    - cabeceras,
    - XSS,
    - cookies,
    - artifacts,
    - duración y metadatos principales.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM vw_execution_summary
                WHERE id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()

        conn.commit()

    return dict(row) if row else None


def list_execution_summaries(
    dsn: str,
    limit: int = 20,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Lista ejecuciones recientes desde la vista de resumen.

    Se usa en:
    - página principal,
    - historial,
    - posibles endpoints/API de consulta.
    """
    safe_limit = int(limit or 20)
    safe_offset = int(offset or 0)

    if safe_limit < 1:
        safe_limit = 20

    if safe_limit > 500:
        safe_limit = 500

    if safe_offset < 0:
        safe_offset = 0

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM vw_execution_summary
                ORDER BY started_at DESC NULLS LAST, id DESC
                LIMIT %s OFFSET %s;
                """,
                (
                    safe_limit,
                    safe_offset,
                ),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]