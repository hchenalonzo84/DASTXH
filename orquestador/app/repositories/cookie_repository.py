"""
cookie_repository.py
- Repositorio de cookies observadas por DASTXH.

Responsabilidad:
- Listar cookies pendientes de interpretación.
- Actualizar interpretación, riesgo, CWE y recomendación.

Nota:
- La inserción inicial de cookies ocurre dentro de
  header_repository.insert_header_results para conservar la lógica
  transaccional original de la capa HTTP.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from repositories.db_connection import connect
from utils import utc_now


def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a JSON string para json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _normalize_risk_level(value: Any) -> Optional[str]:
    """
    Normaliza niveles de riesgo para cookie_checks.
    """
    if value is None:
        return None

    text = str(value).strip().lower()

    if text in ("alta", "media", "baja", "informativa"):
        return text

    return None


def list_cookie_checks_for_interpretation(
    dsn: str,
    execution_id: int,
) -> List[Dict[str, Any]]:
    """
    Devuelve cookies que todavía pueden requerir interpretación.

    Criterio:
    - falta interpretation_humana
    - o falta recommended_action
    - o falta risk_level
    - o falta cwe_mappings
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    cookie_name,
                    cookie_raw,
                    secure,
                    httponly,
                    samesite_present,
                    samesite_value,
                    risk_level,
                    cwe_mappings,
                    interpretation_humana,
                    recommended_action,
                    model_name,
                    interpreted_at,
                    created_at
                FROM cookie_checks
                WHERE execution_id = %s
                  AND (
                    interpretation_humana IS NULL
                    OR recommended_action IS NULL
                    OR risk_level IS NULL
                    OR cwe_mappings IS NULL
                  )
                ORDER BY id ASC;
                """,
                (execution_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(row) for row in rows]


def update_cookie_check_interpretations(
    dsn: str,
    execution_id: int,
    interpretations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza cookies con interpretación por reglas internas e IA.

    Cada elemento puede traer:
    - cookie_check_id, check_id o id
    - risk_level
    - cwe_mappings
    - interpretation_humana
    - recommended_action
    - model_name
    - interpreted_at
    """
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in interpretations:
                raw_cookie_id = item.get(
                    "cookie_check_id",
                    item.get("check_id", item.get("id")),
                )

                try:
                    cookie_check_id = int(raw_cookie_id)
                except Exception:
                    continue

                if cookie_check_id <= 0:
                    continue

                cur.execute(
                    """
                    UPDATE cookie_checks
                    SET risk_level = %s,
                        cwe_mappings = %s::jsonb,
                        interpretation_humana = %s,
                        recommended_action = %s,
                        model_name = %s,
                        interpreted_at = %s
                    WHERE id = %s
                      AND execution_id = %s;
                    """,
                    (
                        _normalize_risk_level(item.get("risk_level")),
                        _json_or_none(item.get("cwe_mappings")),
                        item.get("interpretation_humana"),
                        item.get("recommended_action"),
                        item.get("model_name") or model_name,
                        item.get("interpreted_at") or now,
                        cookie_check_id,
                        execution_id,
                    ),
                )

        conn.commit()