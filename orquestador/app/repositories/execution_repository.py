"""
execution_repository.py
- Repositorio de ejecuciones DASTXH.

Responsabilidad:
- Crear ejecuciones.
- Actualizar estados.
- Marcar ejecuciones como running, finished o failed.
- Consultar historial/resumen de ejecuciones.

Este archivo solo trabaja con persistencia.
No ejecuta curl, hsecscan ni Dalfox.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from repositories.db_connection import connect
from utils import utc_now


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

    Se usa al iniciar una evaluación desde CLI o GUI.

    Campos principales:
    - target_url: URL objetivo.
    - request_source: origen de la ejecución, por ejemplo cli o web.
    - scan_profile: perfil superficial/profundo.
    - enable_hsecscan: indica si se ejecutó capa hsecscan.
    - report_dir: carpeta física de artifacts.
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

    if not row or row.get("id") is None:
        raise RuntimeError("No fue posible obtener el ID de la ejecución insertada.")

    return int(row["id"])


def update_execution_status(
    dsn: str,
    execution_id: int,
    status: str,
    error_message: Optional[str] = None,
    urls_evaluadas: Optional[int] = None,
    finished: bool = False,
) -> None:
    """
    Actualiza el estado de una ejecución.

    Permite:
    - Cambiar status.
    - Guardar error_message.
    - Actualizar urls_evaluadas si aplica.
    - Registrar finished_at cuando finished=True.
    """
    finished_at = utc_now() if finished else None

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            if urls_evaluadas is None:
                cur.execute(
                    """
                    UPDATE executions
                    SET status = %s,
                        error_message = %s,
                        finished_at = COALESCE(%s, finished_at)
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        finished_at,
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
                        finished_at = COALESCE(%s, finished_at)
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        urls_evaluadas,
                        finished_at,
                        execution_id,
                    ),
                )

        conn.commit()


def update_execution_running(dsn: str, execution_id: int) -> None:
    """
    Marca una ejecución como running.
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
    Marca una ejecución como finished o failed.

    Parámetros:
    - ok=True  -> status finished
    - ok=False -> status failed
    """
    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status="finished" if ok else "failed",
        error_message=error_message,
        urls_evaluadas=urls_evaluadas,
        finished=True,
    )


def list_execution_summaries(
    dsn: str,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Lista ejecuciones desde la vista vw_execution_summary.

    Se usa SELECT * para conservar compatibilidad con la vista actual.
    Si la vista ya tiene columnas adicionales de reporte general,
    también serán devueltas.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM vw_execution_summary
                ORDER BY started_at DESC
                LIMIT %s OFFSET %s;
                """,
                (limit, offset),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]


def get_execution_summary(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene el resumen de una ejecución desde vw_execution_summary.
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