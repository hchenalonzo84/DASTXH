"""
db.py
- Acceso a la base de datos propia del laboratorio xss-lab.
- Esta BD es independiente de la BD principal de DASTXH.
- Aquí se guardan productos y reseñas para simular escenarios
  más reales de búsqueda, detalle de producto y XSS persistente.
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
        raise RuntimeError("LAB_DATABASE_URL no está configurada en xss-lab.")
    return dsn


def connect():
    """
    Crea una conexión a PostgreSQL devolviendo filas tipo diccionario.
    """
    return psycopg.connect(get_dsn(), row_factory=dict_row)


def ping_db() -> None:
    """
    Verificación simple de conectividad.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.commit()


def list_products(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Devuelve productos recientes para la portada.
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
    Obtiene un producto por slug.
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
    Busca productos por nombre, resumen o descripción.

    Nota:
    la búsqueda en sí solo consulta la BD.
    La vulnerabilidad reflejada se demostrará en la vista,
    donde el parámetro q se mostrará de forma insegura.
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


def list_reviews_for_product(product_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Devuelve reseñas de un producto.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    product_id,
                    author_name,
                    rating,
                    comment_html,
                    created_at
                FROM reviews
                WHERE product_id = %s
                ORDER BY id DESC
                LIMIT %s;
                """,
                (product_id, limit),
            )
            rows = cur.fetchall()
        conn.commit()

    return [dict(r) for r in rows]


def add_review(
    product_id: int,
    author_name: str,
    rating: int,
    comment_html: str,
) -> int:
    """
    Inserta una reseña nueva y devuelve su id.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reviews (
                    product_id,
                    author_name,
                    rating,
                    comment_html
                )
                VALUES (%s, %s, %s, %s)
                RETURNING id;
                """,
                (product_id, author_name, rating, comment_html),
            )
            row = cur.fetchone()
        conn.commit()

    if not row or "id" not in row:
        raise RuntimeError("No se pudo obtener el id de la reseña insertada.")

    return int(row["id"])