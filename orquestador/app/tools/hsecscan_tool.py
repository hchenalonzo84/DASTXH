"""
hsecscan_tool.py
- CAPA 2: hsecscan (segunda capa)
- Se invoca como comando (hsecscan corre con Python2 internamente).
"""

from __future__ import annotations

from config import UA
from utils import run_cmd


def run_hsecscan(url: str) -> tuple[int, str]:
    """
    Ejecuta hsecscan y devuelve:
    - tool_rc
    - raw_output (stdout+stderr combinado)
    """
    cmd = ["hsecscan", "-i", "-u", url, "-U", UA]
    r = run_cmd(cmd)
    raw = (r.out or "") + ("\n" + r.err if r.err else "")
    return r.rc, raw