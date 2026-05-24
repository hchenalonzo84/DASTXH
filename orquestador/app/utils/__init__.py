"""
utils/__init__.py
- Punto central de exportación para utilidades comunes de DASTXH.

Objetivo:
- Reemplazar el antiguo archivo utils.py por un paquete utils/.
- Mantener compatibilidad con imports existentes como:
      from utils import ensure_dir, wait_for_db
- Permitir que el proyecto crezca separando utilidades por responsabilidad.

Este archivo reexporta funciones desde:
- command_utils.py
- datetime_utils.py
- db_utils.py
- file_utils.py
- json_utils.py
- text_utils.py
"""

from __future__ import annotations

from .command_utils import CmdResult, run_cmd
from .datetime_utils import (
    execution_status_label,
    format_local_datetime,
    parse_datetime_value,
    professional_report_status_label,
    report_change_type_label,
    ts_folder,
    utc_now,
)
from .db_utils import wait_for_db
from .file_utils import ensure_dir, load_urls_from_file, safe_read_text
from .json_utils import write_json
from .text_utils import safe_text


__all__ = [
    # command_utils
    "CmdResult",
    "run_cmd",

    # datetime_utils
    "utc_now",
    "ts_folder",
    "parse_datetime_value",
    "format_local_datetime",
    "execution_status_label",
    "professional_report_status_label",
    "report_change_type_label",

    # db_utils
    "wait_for_db",

    # file_utils
    "ensure_dir",
    "safe_read_text",
    "load_urls_from_file",

    # json_utils
    "write_json",

    # text_utils
    "safe_text",
]