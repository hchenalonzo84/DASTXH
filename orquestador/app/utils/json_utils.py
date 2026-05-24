"""
json_utils.py
- Utilidades para escritura de JSON.

Responsabilidades:
- Escribir objetos JSON con UTF-8.
- Mantener formato legible para artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json(path: Path, obj: Any) -> None:
    """
    Escribe un objeto como JSON en disco.

    Configuración:
    - UTF-8.
    - ensure_ascii=False para conservar español.
    - indent=2 para lectura humana.
    """
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )