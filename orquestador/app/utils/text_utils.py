"""
text_utils.py
- Utilidades generales de texto.

Responsabilidades:
- Normalizar valores a texto seguro.
- Evitar repetir helpers pequeños en múltiples servicios.
"""

from __future__ import annotations

from typing import Any


def safe_text(value: Any, default: str = "") -> str:
    """
    Convierte cualquier valor a texto seguro.

    Si el valor es None o queda vacío después de strip(),
    devuelve el valor por defecto.
    """
    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return text