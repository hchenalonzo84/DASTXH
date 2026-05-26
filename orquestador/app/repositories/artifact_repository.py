"""
artifact_repository.py
- Repositorio de artifacts/evidencias generadas por DASTXH.

Responsabilidad:
- Registrar archivos generados por una ejecución.
- Listar archivos asociados a una ejecución.

Ejemplos:
- report.md
- report.html
- report.pdf
- headers.json
- hsecscan.txt
- dalfox.json
- dalfox.txt
- run_meta.json
- PDFs del reporte general
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from repositories.db_connection import connect


def register_artifact(
    dsn: str,
    execution_id: int,
    artifact_type: str,
    file_name: str,
    relative_path: str,
    mime_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
) -> int:
    """
    Registra o actualiza un artifact y devuelve su ID.

    Se usa UPDATE + INSERT para no depender de que exista
    una restricción UNIQUE en la base de datos.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE artifacts
                SET artifact_type = %s,
                    file_name = %s,
                    mime_type = %s,
                    size_bytes = %s
                WHERE execution_id = %s
                  AND relative_path = %s
                RETURNING id;
                """,
                (
                    artifact_type,
                    file_name,
                    mime_type,
                    size_bytes,
                    execution_id,
                    relative_path,
                ),
            )
            row = cur.fetchone()

            if row and row.get("id") is not None:
                artifact_id = int(row["id"])
            else:
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
                    RETURNING id;
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
                inserted = cur.fetchone()

                if not inserted or inserted.get("id") is None:
                    raise RuntimeError("No fue posible registrar el artifact.")

                artifact_id = int(inserted["id"])

        conn.commit()

    return artifact_id


def list_artifacts(dsn: str, execution_id: int) -> List[Dict[str, Any]]:
    """
    Devuelve los artifacts asociados a una ejecución.
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

    return [dict(row) for row in rows]