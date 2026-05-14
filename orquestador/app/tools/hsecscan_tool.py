"""
hsecscan_tool.py
- CAPA 2: hsecscan (segunda capa)
- Se invoca como comando (hsecscan corre con Python2 internamente).

Objetivo actual:
- Mantener run_hsecscan(url) sin romper compatibilidad.
- Agregar parse_hsecscan_output(raw_output) para convertir la salida cruda
  de hsecscan en una estructura que luego pueda mostrarse mejor en la GUI.

La salida real de hsecscan suele venir en secciones como:
- >> RESPONSE INFO <<
- >> RESPONSE HEADERS DETAILS <<
- >> RESPONSE MISSING HEADERS <<
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from config import UA
from utils import run_cmd


# ==========================================================
# EJECUCIÓN DE HSECSCAN
# ==========================================================

def run_hsecscan(url: str) -> tuple[int, str]:
    """
    Ejecuta hsecscan y devuelve:
    - tool_rc
    - raw_output (stdout+stderr combinado)

    IMPORTANTE:
    Esta firma se mantiene igual para no romper scanner_service.py.
    """
    cmd = ["hsecscan", "-i", "-u", url, "-U", UA]
    r = run_cmd(cmd)
    raw = (r.out or "") + ("\n" + r.err if r.err else "")
    return r.rc, raw


# ==========================================================
# HELPERS DE TEXTO
# ==========================================================

def _clean_text(value: Any) -> str:
    """
    Normaliza texto simple:
    - convierte None en ""
    - elimina espacios excesivos
    - conserva el contenido en una sola línea
    """
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return " ".join(text.split())


def _safe_int(value: Any) -> Optional[int]:
    """
    Convierte un valor a entero si es posible.
    Si no se puede convertir, devuelve None.
    """
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _extract_section(raw_output: str, section_name: str) -> str:
    """
    Extrae el contenido de una sección de hsecscan.

    Ejemplo de marcador:
    >> RESPONSE INFO <<
    """
    raw = raw_output or ""

    pattern = (
        r">>\s*"
        + re.escape(section_name)
        + r"\s*<<\s*"
        + r"(.*?)(?=\n>>\s*[A-Z0-9 _-]+\s*<<|\Z)"
    )

    match = re.search(pattern, raw, flags=re.IGNORECASE | re.DOTALL)

    if not match:
        return ""

    return match.group(1).strip()


def _split_first_colon(line: str) -> tuple[str, str]:
    """
    Divide una línea por el primer ':'.

    Esto es importante porque campos como CWE pueden contener otros ':' en el valor:
    CWE: CWE-79: Improper Neutralization...
    """
    if ":" not in line:
        return line.strip(), ""

    left, right = line.split(":", 1)
    return left.strip(), right.strip()


# ==========================================================
# PARSEO DE RESPONSE INFO
# ==========================================================

def _parse_response_info(section: str) -> Dict[str, Any]:
    """
    Parsea la sección:

    >> RESPONSE INFO <<

    Devuelve:
    - url
    - status_code
    - headers observados como lista, preservando duplicados como Set-Cookie
    """
    response_info: Dict[str, Any] = {
        "url": None,
        "status_code": None,
        "headers": [],
    }

    if not section:
        return response_info

    in_headers_block = False

    for raw_line in section.splitlines():
        line = raw_line.rstrip()

        if not line.strip():
            continue

        stripped = line.strip()

        if stripped.lower().startswith("url:"):
            _label, value = _split_first_colon(stripped)
            response_info["url"] = _clean_text(value)
            continue

        if stripped.lower().startswith("code:"):
            _label, value = _split_first_colon(stripped)
            response_info["status_code"] = _safe_int(value)
            continue

        if stripped.lower() == "headers:":
            in_headers_block = True
            continue

        if in_headers_block:
            header_name, header_value = _split_first_colon(stripped)

            if not header_name:
                continue

            response_info["headers"].append(
                {
                    "header_name": header_name,
                    "value": header_value,
                }
            )

    return response_info


# ==========================================================
# PARSEO DE REGISTROS DE CABECERAS
# ==========================================================

_FIELD_MAP = {
    "Header Field Name": "header_name",
    "Value": "value",
    "Reference": "reference",
    "Security Description": "security_description",
    "Security Reference": "security_reference",
    "Recommendations": "recommendations",
    "CWE": "cwe",
    "CWE URL": "cwe_url",
    "HTTPS": "https",
}


def _field_key_from_line(line: str) -> tuple[Optional[str], str]:
    """
    Detecta si una línea empieza con un campo conocido de hsecscan.

    Devuelve:
    - key interna normalizada, por ejemplo "header_name"
    - value del campo
    """
    if ":" not in line:
        return None, ""

    label, value = _split_first_colon(line)

    key = _FIELD_MAP.get(label)

    if not key:
        return None, ""

    return key, value


def _finalize_header_record(record: Dict[str, Any], record_type: str) -> Optional[Dict[str, Any]]:
    """
    Normaliza y completa un registro de hsecscan.

    record_type:
    - observed: cabecera presente con detalle de seguridad
    - missing: cabecera faltante reportada por hsecscan
    """
    header_name = _clean_text(record.get("header_name"))

    if not header_name:
        return None

    normalized: Dict[str, Any] = {
        "record_type": record_type,
        "header_name": header_name,
        "value": _clean_text(record.get("value")) or None,
        "reference": _clean_text(record.get("reference")) or None,
        "security_description": _clean_text(record.get("security_description")) or None,
        "security_reference": _clean_text(record.get("security_reference")) or None,
        "recommendations": _clean_text(record.get("recommendations")) or None,
        "cwe": _clean_text(record.get("cwe")) or None,
        "cwe_url": _clean_text(record.get("cwe_url")) or None,
        "https": _clean_text(record.get("https")) or None,
    }

    normalized["risk_level"] = _infer_hsecscan_risk_level(normalized)
    normalized["display_status"] = _build_display_status(normalized)

    return normalized


def _parse_header_records(section: str, record_type: str) -> List[Dict[str, Any]]:
    """
    Parsea registros repetidos de hsecscan.

    Cada registro normalmente inicia con:
    Header Field Name: ...

    Luego puede traer:
    Value:
    Reference:
    Security Description:
    Security Reference:
    Recommendations:
    CWE:
    CWE URL:
    HTTPS:
    """
    if not section:
        return []

    records: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    current_key: Optional[str] = None

    for raw_line in section.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        key, value = _field_key_from_line(line)

        # Nuevo campo reconocido.
        if key:
            # Si empieza un nuevo Header Field Name, cerramos el registro anterior.
            if key == "header_name" and current.get("header_name"):
                finalized = _finalize_header_record(current, record_type=record_type)

                if finalized:
                    records.append(finalized)

                current = {}

            current[key] = value.strip()
            current_key = key
            continue

        # Línea de continuación del campo anterior.
        if current_key:
            previous_value = str(current.get(current_key, "") or "").strip()
            continuation = line.strip()

            if previous_value:
                current[current_key] = f"{previous_value} {continuation}"
            else:
                current[current_key] = continuation

    # Cerrar último registro.
    if current.get("header_name"):
        finalized = _finalize_header_record(current, record_type=record_type)

        if finalized:
            records.append(finalized)

    return records


# ==========================================================
# CLASIFICACIÓN SIMPLE PARA UI FUTURA
# ==========================================================

def _infer_hsecscan_risk_level(record: Dict[str, Any]) -> str:
    """
    Asigna un nivel orientativo para mostrar en UI.

    Esta clasificación NO reemplaza reglas formales.
    Solo ayuda a ordenar/visualizar la salida de hsecscan.
    """
    record_type = str(record.get("record_type") or "").lower()
    header_name = str(record.get("header_name") or "").strip().lower()
    cwe = str(record.get("cwe") or "").lower()

    if record_type == "missing":
        high_headers = {
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
        }

        medium_headers = {
            "x-xss-protection",
            "pragma",
            "cache-control",
            "referrer-policy",
            "permissions-policy",
            "content-security-policy-report-only",
        }

        if header_name in high_headers:
            return "alta"

        if header_name in medium_headers:
            return "media"

        if "cwe-79" in cwe or "cwe-693" in cwe:
            return "media"

        return "baja"

    # Cabeceras presentes, pero con advertencia.
    if header_name == "set-cookie":
        return "media"

    if header_name == "server" or "cwe-200" in cwe:
        return "baja"

    if header_name == "content-type":
        return "baja"

    return "informativa"


def _build_display_status(record: Dict[str, Any]) -> str:
    """
    Construye un estado amigable para UI futura.
    """
    record_type = str(record.get("record_type") or "").lower()

    if record_type == "missing":
        return "Faltante"

    return "Observada"


# ==========================================================
# RESUMEN ESTRUCTURADO
# ==========================================================

def _build_header_presence_index(headers: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Crea un índice simple de cabeceras observadas en RESPONSE INFO.

    Se conserva lista de valores porque puede haber cabeceras repetidas,
    especialmente Set-Cookie.
    """
    result: Dict[str, List[str]] = {}

    for item in headers:
        name = _clean_text(item.get("header_name"))

        if not name:
            continue

        value = _clean_text(item.get("value"))
        key = name.lower()

        if key not in result:
            result[key] = []

        result[key].append(value)

    return result


def _build_summary(
    response_info: Dict[str, Any],
    observed_headers: List[Dict[str, Any]],
    missing_headers: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construye un resumen útil para scanner_service.py, db.py o la GUI.
    """
    response_headers = response_info.get("headers", []) or []
    presence_index = _build_header_presence_index(response_headers)

    missing_header_names = [
        item.get("header_name")
        for item in missing_headers
        if item.get("header_name")
    ]

    observed_header_names = [
        item.get("header_name")
        for item in observed_headers
        if item.get("header_name")
    ]

    return {
        "status_code": response_info.get("status_code"),
        "response_headers_count": len(response_headers),
        "observed_security_headers_count": len(observed_headers),
        "missing_security_headers_count": len(missing_headers),
        "total_hsecscan_records": len(observed_headers) + len(missing_headers),
        "missing_header_names": missing_header_names,
        "observed_header_names": observed_header_names,
        "has_set_cookie": "set-cookie" in presence_index,
        "has_server_disclosure": "server" in presence_index,
        "has_content_security_policy": "content-security-policy" in presence_index,
        "has_x_frame_options": "x-frame-options" in presence_index,
        "has_x_content_type_options": "x-content-type-options" in presence_index,
        "has_strict_transport_security": "strict-transport-security" in presence_index,
    }


# ==========================================================
# API PÚBLICA DEL PARSER
# ==========================================================

def parse_hsecscan_output(raw_output: str) -> Dict[str, Any]:
    """
    Convierte la salida cruda de hsecscan en un diccionario estructurado.

    No lanza excepción si el formato cambia; intenta devolver lo que pueda.

    Retorna:
    {
      "ok": bool,
      "response_info": {...},
      "observed_headers": [...],
      "missing_headers": [...],
      "summary": {...},
      "parse_warnings": [...]
    }
    """
    raw = raw_output or ""
    parse_warnings: List[str] = []

    response_info_section = _extract_section(raw, "RESPONSE INFO")
    observed_headers_section = _extract_section(raw, "RESPONSE HEADERS DETAILS")
    missing_headers_section = _extract_section(raw, "RESPONSE MISSING HEADERS")

    if not response_info_section:
        parse_warnings.append("No se encontró la sección RESPONSE INFO.")

    if not observed_headers_section:
        parse_warnings.append("No se encontró la sección RESPONSE HEADERS DETAILS.")

    if not missing_headers_section:
        parse_warnings.append("No se encontró la sección RESPONSE MISSING HEADERS.")

    response_info = _parse_response_info(response_info_section)

    observed_headers = _parse_header_records(
        observed_headers_section,
        record_type="observed",
    )

    missing_headers = _parse_header_records(
        missing_headers_section,
        record_type="missing",
    )

    summary = _build_summary(
        response_info=response_info,
        observed_headers=observed_headers,
        missing_headers=missing_headers,
    )

    return {
        "ok": bool(raw.strip()),
        "response_info": response_info,
        "observed_headers": observed_headers,
        "missing_headers": missing_headers,
        "summary": summary,
        "parse_warnings": parse_warnings,
    }