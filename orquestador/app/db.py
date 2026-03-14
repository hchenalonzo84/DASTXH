"""
db.py
- Acceso a PostgreSQL usando psycopg (psycopg3).
- Centraliza las operaciones de persistencia para:
  * executions
  * header_results
  * hsecscan_results
  * xss_results
  * artifacts
- También incluye consultas base para:
  * historial
  * detalle de ejecución
  * lista de artifacts

Importante:
- La idea es evitar SQL suelto en main.py, webapp.py o rutas API.
- Así mantenemos la lógica de persistencia en un solo lugar.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from utils import utc_now


# ==========================================================
# CONEXIÓN Y SALUD DE BASE DE DATOS
# ==========================================================

def connect(dsn: str) -> Connection:
    """
    Crea y devuelve una conexión a PostgreSQL.

    Usamos row_factory=dict_row para que las consultas SELECT
    devuelvan diccionarios en lugar de tuplas, lo cual resulta
    más cómodo para la GUI, la API y el backend en general.
    """
    return psycopg.connect(dsn, row_factory=dict_row)


def ping_db(dsn: str) -> None:
    """
    Prueba rápida de conectividad a la base de datos.

    Si esta función falla, el llamador puede reintentar
    hasta que PostgreSQL esté disponible.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.commit()


# ==========================================================
# EJECUCIONES
# ==========================================================

def insert_execution(
    dsn: str,
    target_url: str,
    request_source: str = "cli",
    report_dir: Optional[str] = None,
    status: str = "initiated",
    urls_ingresadas: int = 1,
    urls_evaluadas: int = 0,
) -> int:
    """
    Inserta una nueva ejecución en la tabla executions
    y devuelve el id generado.

    Parámetros:
    - target_url: URL objetivo
    - request_source: origen de la solicitud ('cli', 'web', 'api')
    - report_dir: ruta lógica de reportes dentro de /work
    - status: estado inicial ('initiated', 'running', 'finished', 'failed')
    - urls_ingresadas: cantidad de URLs recibidas
    - urls_evaluadas: cantidad de URLs efectivamente evaluadas
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
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    target_url,
                    utc_now(),
                    status,
                    request_source,
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
    - execution_id: id de la ejecución
    - status: nuevo estado
    - error_message: mensaje de error opcional
    - urls_evaluadas: cantidad de URLs evaluadas opcional
    - finished: si es True, se asigna finished_at = ahora;
                si es False, finished_at se deja igual
    """
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
                        utc_now(),
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
                        utc_now(),
                        execution_id,
                    ),
                )
        conn.commit()


def update_execution_running(dsn: str, execution_id: int) -> None:
    """
    Marca una ejecución como 'running'.
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
    Marca la ejecución como finalizada correctamente o fallida.

    Si ok=True:
    - status = 'finished'

    Si ok=False:
    - status = 'failed'
    """
    new_status = "finished" if ok else "failed"

    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status=new_status,
        error_message=error_message,
        urls_evaluadas=urls_evaluadas,
        finished=True,
    )


# ==========================================================
# RESULTADOS CAPA 1: HEADERS CUSTOM
# ==========================================================

def insert_header_results(
    dsn: str,
    execution_id: int,
    hdr_eval: Dict[str, Any],
    raw_headers_json: Dict[str, Any],
) -> None:
    """
    Inserta los resultados de la Capa 1 (curl custom).

    hdr_eval debe contener al menos:
    - headers_evaluadas
    - headers_presentes
    - cumplimiento_pct
    - present
    - missing
    - cookies_flags
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO header_results (
                    execution_id,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    present_json,
                    missing_json,
                    raw_headers_json,
                    cookies_flags_json
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb
                );
                """,
                (
                    execution_id,
                    int(hdr_eval["headers_evaluadas"]),
                    int(hdr_eval["headers_presentes"]),
                    float(hdr_eval["cumplimiento_pct"]),
                    json.dumps(hdr_eval.get("present", []), ensure_ascii=False),
                    json.dumps(hdr_eval.get("missing", []), ensure_ascii=False),
                    json.dumps(raw_headers_json, ensure_ascii=False),
                    json.dumps(hdr_eval.get("cookies_flags", []), ensure_ascii=False),
                ),
            )
        conn.commit()


# ==========================================================
# RESULTADOS CAPA 2: HSECSCAN
# ==========================================================

def insert_hsecscan_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    raw_output: str,
) -> None:
    """
    Inserta los resultados de la Capa 2 (hsecscan).
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hsecscan_results (
                    execution_id,
                    tool_rc,
                    raw_output
                )
                VALUES (%s, %s, %s);
                """,
                (
                    execution_id,
                    int(tool_rc),
                    raw_output,
                ),
            )
        conn.commit()


# ==========================================================
# RESULTADOS CAPA 3: DALFOX / XSS
# ==========================================================

def insert_xss_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    findings_count: int,
    summary_json: Any,
    raw_output: str,
) -> None:
    """
    Inserta los resultados de la Capa 3 (Dalfox / XSS).

    Novedad respecto a la versión anterior:
    - ahora también registramos tool_rc
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO xss_results (
                    execution_id,
                    tool_rc,
                    findings_count,
                    summary_json,
                    raw_output
                )
                VALUES (%s, %s, %s, %s::jsonb, %s);
                """,
                (
                    execution_id,
                    int(tool_rc),
                    int(findings_count),
                    json.dumps(summary_json, ensure_ascii=False),
                    raw_output,
                ),
            )
        conn.commit()


# ==========================================================
# ARTIFACTS / EVIDENCIAS
# ==========================================================

def register_artifact(
    dsn: str,
    execution_id: int,
    artifact_type: str,
    file_name: str,
    relative_path: str,
    mime_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
) -> None:
    """
    Registra un artifact generado por una ejecución.

    Usamos UPSERT para que, si se vuelve a registrar el mismo
    relative_path para la misma ejecución, se actualicen los metadatos
    en lugar de fallar.

    Ejemplos de artifact_type:
    - report_md
    - report_html
    - report_pdf
    - headers_json
    - hsecscan_txt
    - dalfox_json
    - dalfox_txt
    - run_meta_json
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO artifacts (
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (execution_id, relative_path)
                DO UPDATE SET
                    artifact_type = EXCLUDED.artifact_type,
                    file_name = EXCLUDED.file_name,
                    mime_type = EXCLUDED.mime_type,
                    size_bytes = EXCLUDED.size_bytes;
                """,
                (
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes,
                ),
            )
        conn.commit()


def list_artifacts(dsn: str, execution_id: int) -> List[Dict[str, Any]]:
    """
    Devuelve la lista de artifacts de una ejecución,
    ordenados por created_at y luego por id.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes,
                    created_at
                FROM artifacts
                WHERE execution_id = %s
                ORDER BY created_at ASC, id ASC;
                """,
                (execution_id,),
            )
            rows = cur.fetchall()
        conn.commit()

    return [dict(r) for r in rows]


# ==========================================================
# CONSULTAS DE HISTORIAL Y DETALLE
# ==========================================================

def list_execution_summaries(
    dsn: str,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Lista ejecuciones desde la vista vw_execution_summary.

    Esta función será útil para:
    - historial en GUI web
    - endpoints API
    - consultas manuales internas
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    target_url,
                    started_at,
                    finished_at,
                    status,
                    request_source,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    hsecscan_rc,
                    dalfox_rc,
                    xss_findings_count,
                    artifacts_count
                FROM vw_execution_summary
                ORDER BY started_at DESC
                LIMIT %s OFFSET %s;
                """,
                (limit, offset),
            )
            rows = cur.fetchall()
        conn.commit()

    return [dict(r) for r in rows]


def get_execution_summary(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene una sola ejecución desde la vista de resumen.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    target_url,
                    started_at,
                    finished_at,
                    status,
                    request_source,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    hsecscan_rc,
                    dalfox_rc,
                    xss_findings_count,
                    artifacts_count
                FROM vw_execution_summary
                WHERE id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()
        conn.commit()

    return dict(row) if row else None


def get_execution_detail(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Devuelve detalle enriquecido de una ejecución.

    Incluye:
    - datos base de executions
    - resultados de headers
    - resultados de hsecscan
    - resultados de xss
    - artifacts asociados

    Este detalle es muy útil para una futura página:
    /executions/{id}
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    e.id,
                    e.target_url,
                    e.started_at,
                    e.finished_at,
                    e.status,
                    e.error_message,
                    e.request_source,
                    e.urls_ingresadas,
                    e.urls_evaluadas,
                    e.report_dir,

                    hr.headers_evaluadas,
                    hr.headers_presentes,
                    hr.cumplimiento_pct,
                    hr.present_json,
                    hr.missing_json,
                    hr.raw_headers_json,
                    hr.cookies_flags_json,

                    hs.tool_rc AS hsecscan_rc,
                    hs.raw_output AS hsecscan_raw_output,

                    xr.tool_rc AS dalfox_rc,
                    xr.findings_count,
                    xr.summary_json,
                    xr.raw_output AS dalfox_raw_output
                FROM executions e
                LEFT JOIN header_results hr
                    ON hr.execution_id = e.id
                LEFT JOIN hsecscan_results hs
                    ON hs.execution_id = e.id
                LEFT JOIN xss_results xr
                    ON xr.execution_id = e.id
                WHERE e.id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        return None

    detail = dict(row)
    detail["artifacts"] = list_artifacts(dsn, execution_id)
    return detail