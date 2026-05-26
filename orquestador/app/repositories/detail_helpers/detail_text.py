"""
detail_text.py
- Helpers de texto y normalización visual para el detalle de ejecución.

Responsabilidad:
- Limpiar textos para presentación.
- Detectar valores vacíos/no informativos.
- Normalizar campos JSON que deberían ser listas.
- Obtener el primer texto útil de una lista.

Nota:
- Se llama detail_text.py para evitar conflicto con otros text_utils.py
  existentes en el proyecto.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional


def clean_display_text(value: Any) -> str:
    """
    Normaliza texto para uso visual.

    Hace:
    - convierte None en cadena vacía;
    - elimina espacios al inicio/final;
    - reemplaza saltos de línea por espacios;
    - compacta espacios repetidos.

    Esto evita que payloads, evidencia o campos IA rompan la tabla visual.
    """
    text = str(value or "").strip()
    return " ".join(text.replace("\n", " ").replace("\r", " ").split())


def is_empty_visual_value(value: Any) -> bool:
    """
    Determina si un valor debe considerarse vacío o no informativo.

    Se usa principalmente para decidir si un hallazgo XSS tiene suficiente
    información real para mostrarse al usuario.
    """
    text = clean_display_text(value).lower()
    return text in ("", "-", "none", "null", "unknown", "desconocido")


def as_list(value: Any) -> List[Any]:
    """
    Normaliza campos json/jsonb que deberían venir como lista.

    PostgreSQL normalmente devuelve jsonb como lista/dict directamente.
    Aun así, se tolera texto JSON por seguridad.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        raw = value.strip()

        if not raw:
            return []

        try:
            parsed = json.loads(raw)

            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [value]

    return []


def first_non_empty_text(values: Any) -> Optional[str]:
    """
    Devuelve el primer texto no vacío dentro de una lista.

    Se usa para tomar un payload/evidencia representativa de un grupo XSS.
    """
    for item in as_list(values):
        text = clean_display_text(item)

        if text:
            return text

    return None