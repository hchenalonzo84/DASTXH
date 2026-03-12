"""
utils.py
- Helpers de tiempo, paths, IO y ejecución de comandos.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from subprocess import run, PIPE
from typing import Any, Callable, List, Optional


def utc_now() -> datetime:
    """Fecha/hora actual en UTC."""
    return datetime.now(timezone.utc)


def ts_folder(dt: datetime) -> str:
    """Nombre carpeta para reportes: YYYYMMDD_HHMMSS."""
    return dt.strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: Path) -> None:
    """Crea directorio si no existe."""
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> None:
    """Escribe JSON con indent y UTF-8."""
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def safe_read_text(path: Path) -> str:
    """Lee texto seguro (si falla, retorna vacío)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def load_urls_from_file(path: Path) -> List[str]:
    """
    Lee URLs desde un archivo:
    - ignora líneas vacías
    - ignora comentarios (#)
    - deduplica manteniendo orden
    """
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    urls: List[str] = []
    for ln in raw:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        urls.append(s)

    seen = set()
    out: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def wait_for_db(ping_fn: Callable[[], None], timeout_s: int = 40) -> None:
    """Espera a DB hasta timeout."""
    start = time.time()
    while True:
        try:
            ping_fn()
            return
        except Exception as e:
            if time.time() - start > timeout_s:
                raise RuntimeError(f"DB no disponible tras {timeout_s}s: {e}") from e
            time.sleep(1)


@dataclass
class CmdResult:
    rc: int
    out: str
    err: str


def run_cmd(cmd: List[str], timeout_s: Optional[int] = None) -> CmdResult:
    """Ejecuta comando y captura stdout/stderr."""
    p = run(cmd, stdout=PIPE, stderr=PIPE, text=True, timeout=timeout_s)
    return CmdResult(p.returncode, p.stdout or "", p.stderr or "")