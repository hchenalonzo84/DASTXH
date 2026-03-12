"""
db.py
- Acceso a PostgreSQL (psycopg).
- Encapsula inserciones/updates para evitar SQL suelto en main.py.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import psycopg
from psycopg import Connection

from utils import utc_now


def connect(dsn: str) -> Connection:
    """Crea conexión a Postgres."""
    return psycopg.connect(dsn)


def ping_db(dsn: str) -> None:
    """
    Prueba rápida de conectividad.
    Si esto falla, main.py esperará/reintentará.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.commit()


def insert_execution(dsn: str, target_url: str) -> int:
    """Inserta ejecución iniciada y devuelve id."""
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO executions (target_url, started_at, status, urls_ingresadas, urls_evaluadas)
                VALUES (%s, %s, 'initiated', 1, 0)
                RETURNING id;
                """,
                (target_url, utc_now()),
            )
            (eid,) = cur.fetchone()
        conn.commit()
        return int(eid)


def update_execution_finished(dsn: str, execution_id: int, ok: bool, error_message: Optional[str] = None) -> None:
    """Marca ejecución como finished o failed."""
    status = "finished" if ok else "failed"
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE executions
                SET finished_at = %s,
                    status = %s,
                    error_message = %s,
                    urls_evaluadas = %s
                WHERE id = %s;
                """,
                (utc_now(), status, error_message, 1 if ok else 0, execution_id),
            )
        conn.commit()


def insert_header_results(dsn: str, execution_id: int, hdr_eval: Dict[str, Any], raw_headers_json: Dict[str, Any]) -> None:
    """Inserta resultados capa 1 (curl custom)."""
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO header_results
                  (execution_id, headers_evaluadas, headers_presentes, cumplimiento_pct,
                   present_json, missing_json, raw_headers_json, cookies_flags_json)
                VALUES
                  (%s, %s, %s, %s,
                   %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb);
                """,
                (
                    execution_id,
                    int(hdr_eval["headers_evaluadas"]),
                    int(hdr_eval["headers_presentes"]),
                    float(hdr_eval["cumplimiento_pct"]),
                    json.dumps(hdr_eval["present"], ensure_ascii=False),
                    json.dumps(hdr_eval["missing"], ensure_ascii=False),
                    json.dumps(raw_headers_json, ensure_ascii=False),
                    json.dumps(hdr_eval.get("cookies_flags", []), ensure_ascii=False),
                ),
            )
        conn.commit()


def insert_hsecscan_results(dsn: str, execution_id: int, tool_rc: int, raw_output: str) -> None:
    """Inserta resultados capa 2 (hsecscan)."""
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hsecscan_results (execution_id, tool_rc, raw_output)
                VALUES (%s, %s, %s);
                """,
                (execution_id, int(tool_rc), raw_output),
            )
        conn.commit()


def insert_xss_results(dsn: str, execution_id: int, findings_count: int, summary_json: Any, raw_output: str) -> None:
    """Inserta resultados capa 3 (dalfox)."""
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO xss_results (execution_id, findings_count, summary_json, raw_output)
                VALUES (%s, %s, %s::jsonb, %s);
                """,
                (execution_id, int(findings_count), json.dumps(summary_json, ensure_ascii=False), raw_output),
            )
        conn.commit()