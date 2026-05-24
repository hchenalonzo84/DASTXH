"""
command_utils.py
- Utilidades para ejecución de comandos externos.

Responsabilidades:
- Ejecutar herramientas externas.
- Capturar stdout, stderr y código de salida.
"""

from __future__ import annotations

from dataclasses import dataclass
from subprocess import PIPE, run
from typing import List, Optional


@dataclass
class CmdResult:
    """
    Resultado normalizado de un comando externo.

    Atributos:
    - rc: código de salida.
    - out: salida estándar.
    - err: salida de error.
    """
    rc: int
    out: str
    err: str


def run_cmd(cmd: List[str], timeout_s: Optional[int] = None) -> CmdResult:
    """
    Ejecuta un comando y captura stdout/stderr.

    No interpreta la salida.
    Solo devuelve el resultado para que la capa correspondiente lo procese.
    """
    process = run(
        cmd,
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        timeout=timeout_s,
    )

    return CmdResult(
        rc=process.returncode,
        out=process.stdout or "",
        err=process.stderr or "",
    )