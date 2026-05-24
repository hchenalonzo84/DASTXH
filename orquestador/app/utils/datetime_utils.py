"""
datetime_utils.py
- Utilidades de fecha/hora para DASTXH.

Responsabilidades:
- Obtener hora UTC.
- Generar nombres de carpeta por timestamp.
- Convertir fechas guardadas en UTC a hora local visible.
- Traducir estados internos a etiquetas en español.

Regla global:
- PostgreSQL puede guardar fechas en UTC.
- La GUI y los PDF deben mostrar fechas en America/Guatemala.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

import config


def utc_now() -> datetime:
    """
    Devuelve la fecha/hora actual en UTC.

    Se usa para registrar eventos de forma consistente,
    independiente de la zona horaria del contenedor o del host.
    """
    return datetime.now(timezone.utc)


def ts_folder(dt: datetime) -> str:
    """
    Construye un nombre de carpeta para reportes.

    Formato:
        YYYYMMDD_HHMMSS
    """
    return dt.strftime("%Y%m%d_%H%M%S")


def get_display_timezone() -> ZoneInfo:
    """
    Devuelve la zona horaria configurada para mostrar fechas.

    Por defecto:
        America/Guatemala
    """
    timezone_name = getattr(config, "DISPLAY_TIMEZONE", "America/Guatemala")

    try:
        return ZoneInfo(timezone_name)
    except Exception:
        return ZoneInfo("America/Guatemala")


def get_display_datetime_format() -> str:
    """
    Devuelve el formato global visible de fecha/hora.
    """
    return getattr(config, "DISPLAY_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")


def parse_datetime_value(value: Any) -> Optional[datetime]:
    """
    Convierte un valor recibido desde PostgreSQL o string a datetime.

    Soporta:
    - datetime con zona horaria.
    - datetime sin zona horaria.
    - string ISO con offset.
    - string ISO con Z.
    - string compatible con datetime.fromisoformat.

    Regla:
    - Si el valor no tiene zona horaria, se asume UTC.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(text)
        except Exception:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def format_local_datetime(value: Any, default: str = "-") -> str:
    """
    Formatea una fecha para mostrarla en hora local de Guatemala.

    Uso previsto en Jinja:
        {{ detail.started_at|local_datetime }}

    También puede usarse en PDF.
    """
    parsed = parse_datetime_value(value)

    if parsed is None:
        return default

    local_dt = parsed.astimezone(get_display_timezone())
    return local_dt.strftime(get_display_datetime_format())


def execution_status_label(value: Any) -> str:
    """
    Traduce estados internos de ejecución a español.

    Ejemplo:
        finished -> Finalizada
    """
    text = str(value or "").strip()

    if not text:
        return "-"

    labels = getattr(config, "EXECUTION_STATUS_LABELS", {})
    return labels.get(text, text) if isinstance(labels, dict) else text


def professional_report_status_label(value: Any) -> str:
    """
    Traduce estados internos del reporte general a español.
    """
    text = str(value or "").strip()

    if not text:
        return "-"

    labels = getattr(config, "PROFESSIONAL_REPORT_STATUS_LABELS", {})
    return labels.get(text, text) if isinstance(labels, dict) else text


def report_change_type_label(value: Any) -> str:
    """
    Traduce tipos internos de cambio del reporte general a español.

    Ejemplo:
        manual_save -> Guardado manual
    """
    text = str(value or "").strip()

    if not text:
        return "-"

    labels = getattr(config, "PROFESSIONAL_REPORT_CHANGE_TYPE_LABELS", {})
    return labels.get(text, text) if isinstance(labels, dict) else text