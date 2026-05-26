"""
db_connection.py
- Conexión y salud de PostgreSQL para DASTXH.

Responsabilidad:
- Centralizar la creación de conexiones a PostgreSQL.
- Proveer una función simple para verificar conectividad.
- Evitar que cada repositorio repita lógica de conexión.

Nota:
- Este archivo NO contiene consultas de negocio.
- Las consultas de negocio viven en los repositorios específicos.
"""

from __future__ import annotations

import psycopg
from psycopg.rows import dict_row


def connect(dsn: str):
    """
    Crea una conexión a PostgreSQL usando psycopg.

    Parámetros:
    - dsn: cadena de conexión DATABASE_URL.

    Retorna:
    - Conexión configurada para devolver filas como diccionarios.

    Ejemplo de retorno:
    row["id"] en lugar de row[0]
    """
    return psycopg.connect(dsn, row_factory=dict_row)


def ping_db(dsn: str) -> None:
    """
    Verifica que la base de datos esté disponible.

    Lanza excepción si:
    - PostgreSQL no responde.
    - La conexión falla.
    - La consulta SELECT 1 falla.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")

        conn.commit()