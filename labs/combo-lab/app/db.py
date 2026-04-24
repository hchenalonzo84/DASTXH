"""
db.py
- Acceso a la base de datos propia del laboratorio combo-lab.
- Esta BD es independiente de la BD principal de DASTXH.

Objetivo:
- almacenar productos
- permitir búsquedas
- alimentar la vista de catálogo y detalle
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row


def get_dsn() -> str:
    """
    Obtiene la cadena de conexión del laboratorio desde el entorno.
    """
    dsn = os.getenv("LAB_DATABASE_URL")
    if not dsn:
        raise RuntimeError("LAB_DATABASE_URL no está configurada en combo-lab.")
    return dsn


def connect():
    """
    Crea una conexión a PostgreSQL devolviendo filas como diccionarios.
    """
    return psycopg.connect(get_dsn(), row_factory=dict_row)


def ping_db() -> None:
    """
    Verificación simple de conectividad con la BD del laboratorio.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.commit()


def list_products(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Devuelve productos para la portada del laboratorio.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    slug,
                    name,
                    price,
                    short_description,
                    description_html,
                    created_at
                FROM products
                ORDER BY id ASC
                LIMIT %s;
                """,
                (limit,),
            )
            rows = cur.fetchall()
        conn.commit()

    return [dict(r) for r in rows]


def get_product_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    """
    Obtiene un producto por su slug.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    slug,
                    name,
                    price,
                    short_description,
                    description_html,
                    created_at
                FROM products
                WHERE slug = %s;
                """,
                (slug,),
            )
            row = cur.fetchone()
        conn.commit()

    return dict(row) if row else None


def search_products(term: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Busca productos por nombre, descripción corta o HTML descriptivo.
    """
    like_term = f"%{term}%"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    slug,
                    name,
                    price,
                    short_description,
                    description_html,
                    created_at
                FROM products
                WHERE name ILIKE %s
                   OR short_description ILIKE %s
                   OR description_html ILIKE %s
                ORDER BY id ASC
                LIMIT %s;
                """,
                (like_term, like_term, like_term, limit),
            )
            rows = cur.fetchall()
        conn.commit()

    return [dict(r) for r in rows]