"""
file_utils.py
- Utilidades de archivos, carpetas y lectura segura.

Responsabilidades:
- Crear carpetas.
- Leer texto de forma tolerante.
- Cargar listas de URLs desde archivo.
"""

from __future__ import annotations

from pathlib import Path
from typing import List


def ensure_dir(path: Path) -> None:
    """
    Crea un directorio si no existe.

    Se usa para carpetas de trabajo, reportes y artifacts.
    """
    path.mkdir(parents=True, exist_ok=True)


def safe_read_text(path: Path) -> str:
    """
    Lee texto de forma segura.

    Si ocurre un error, retorna cadena vacía.
    Esto evita que un archivo faltante o ilegible detenga todo el pipeline.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def load_urls_from_file(path: Path) -> List[str]:
    """
    Lee URLs desde un archivo de texto.

    Reglas:
    - Ignora líneas vacías.
    - Ignora comentarios que inician con #.
    - Deduplica manteniendo el orden.
    """
    if not path.exists():
        return []

    raw_lines = path.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines()

    urls: List[str] = []

    for line in raw_lines:
        value = line.strip()

        if not value:
            continue

        if value.startswith("#"):
            continue

        urls.append(value)

    seen = set()
    output: List[str] = []

    for url in urls:
        if url in seen:
            continue

        seen.add(url)
        output.append(url)

    return output