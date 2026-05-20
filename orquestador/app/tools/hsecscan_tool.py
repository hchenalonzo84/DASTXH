"""
hsecscan_tool.py
- CAPA 2: hsecscan (segunda capa de contraste para cabeceras HTTP).
- Se invoca como comando externo.
- hsecscan corre internamente con Python 2.7.

Objetivo actual:
- Mantener run_hsecscan(url) sin romper compatibilidad con scanner_service.py.
- Ejecutar hsecscan con reintentos controlados para reducir fallos intermitentes.
- Convertir la salida cruda de hsecscan en una estructura útil para BD, GUI y reportes.
- Detectar errores técnicos como HTTP 403, traceback o salidas no parseables.
- Evitar marcar como ok=True una salida que realmente corresponde a un error de herramienta.

Contexto:
- hsecscan puede fallar contra URLs públicas cuando el servidor responde 403 Forbidden,
  cuando responde diferente entre intentos o cuando urllib2 no maneja bien la respuesta.
- En esos casos puede no generar sus secciones normales:
  * >> RESPONSE INFO <<
  * >> RESPONSE HEADERS DETAILS <<
  * >> RESPONSE MISSING HEADERS <<
- DASTXH debe registrar ese caso como error controlado de la capa complementaria,
  no como “0 registros encontrados”.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from config import UA
from utils import run_cmd


# ==========================================================
# CONFIGURACIÓN INTERNA DE REINTENTOS HSECSCAN
# ==========================================================
# No se coloca en .env por ahora para evitar tocar más archivos.
# Objetivo:
# - reducir fallos intermitentes;
# - no alargar demasiado la ejecución;
# - mantener el cambio aislado en este archivo.
# ==========================================================

HSECSCAN_MAX_ATTEMPTS = 3
HSECSCAN_RETRY_DELAY_SECONDS = 2


# ==========================================================
# EJECUCIÓN DE HSECSCAN
# ==========================================================

def _run_hsecscan_once(url: str) -> tuple[int, str]:
    """
    Ejecuta hsecscan una sola vez y devuelve:
    - tool_rc;
    - raw_output combinado stdout + stderr.

    Esta función es interna. El servicio público sigue siendo run_hsecscan(url).
    """
    cmd = ["hsecscan", "-i", "-u", url, "-U", UA]
    result = run_cmd(cmd)

    raw_output = (result.out or "") + ("\n" + result.err if result.err else "")

    return result.rc, raw_output


def _is_hsecscan_attempt_usable(tool_rc: int, raw_output: str) -> bool:
    """
    Decide si un intento de hsecscan produjo salida estructurada usable.

    Criterio:
    - hsecscan debe terminar con rc=0;
    - el parser debe encontrar estructura real;
    - no debe ser solamente traceback, error HTTP o salida vacía.

    Nota:
    parse_hsecscan_output está definido más abajo, pero Python resuelve
    la función cuando run_hsecscan se ejecuta, no cuando este archivo se carga.
    """
    if tool_rc != 0:
        return False

    parsed = parse_hsecscan_output(raw_output)

    return bool(parsed.get("ok"))


def _build_hsecscan_attempt_header(
    attempt_number: int,
    tool_rc: int,
    usable: bool,
) -> str:
    """
    Construye una línea de trazabilidad para hsecscan.txt.
    """
    status = "usable" if usable else "not_usable"

    return (
        f"[DASTXH] hsecscan attempt={attempt_number} "
        f"tool_rc={tool_rc} status={status}"
    )


def _build_recovered_output(
    url: str,
    attempt_number: int,
    tool_rc: int,
    raw_output: str,
) -> str:
    """
    Devuelve la salida final cuando hsecscan se recupera en un reintento.

    Importante:
    No se incluyen tracebacks completos de intentos fallidos anteriores,
    porque eso haría que el parser detecte un error aunque el último intento
    sí haya generado salida estructurada válida.
    """
    diagnostic = (
        "[DASTXH] hsecscan recovered after retry.\n"
        f"[DASTXH] target={url}\n"
        f"[DASTXH] successful_attempt={attempt_number}\n"
        f"[DASTXH] tool_rc={tool_rc}\n"
    )

    return f"{diagnostic}\n{raw_output}"


def _build_failed_output(
    url: str,
    attempts: List[Dict[str, Any]],
) -> str:
    """
    Devuelve una salida final cuando todos los intentos fallaron.

    En este caso sí se conservan las salidas de cada intento para diagnóstico,
    porque no existe una salida estructurada exitosa que proteger del parser.
    """
    parts: List[str] = [
        "[DASTXH] hsecscan failed after retries.",
        f"[DASTXH] target={url}",
        f"[DASTXH] attempts={len(attempts)}",
        "",
    ]

    for attempt in attempts:
        attempt_number = attempt.get("attempt_number")
        tool_rc = attempt.get("tool_rc")
        usable = attempt.get("usable")
        raw_output = attempt.get("raw_output") or ""

        parts.append(
            _build_hsecscan_attempt_header(
                attempt_number=int(attempt_number or 0),
                tool_rc=int(tool_rc or 0),
                usable=bool(usable),
            )
        )
        parts.append(raw_output)
        parts.append("")

    return "\n".join(parts).strip()


def run_hsecscan(url: str) -> tuple[int, str]:
    """
    Ejecuta hsecscan con reintentos controlados y devuelve:
    - tool_rc;
    - raw_output final.

    Compatibilidad:
    - Esta firma se mantiene igual para no romper scanner_service.py.

    Comportamiento:
    - Si el primer intento genera salida estructurada válida, se usa de inmediato.
    - Si falla, se reintenta hasta HSECSCAN_MAX_ATTEMPTS.
    - Si un intento posterior funciona, se devuelve esa salida exitosa.
    - Si todos fallan, se devuelve la salida diagnóstica con todos los intentos.
    """
    attempts: List[Dict[str, Any]] = []

    for attempt_number in range(1, HSECSCAN_MAX_ATTEMPTS + 1):
        tool_rc, raw_output = _run_hsecscan_once(url)
        usable = _is_hsecscan_attempt_usable(tool_rc, raw_output)

        attempts.append(
            {
                "attempt_number": attempt_number,
                "tool_rc": tool_rc,
                "usable": usable,
                "raw_output": raw_output,
            }
        )

        if usable:
            return (
                tool_rc,
                _build_recovered_output(
                    url=url,
                    attempt_number=attempt_number,
                    tool_rc=tool_rc,
                    raw_output=raw_output,
                ),
            )

        if attempt_number < HSECSCAN_MAX_ATTEMPTS:
            time.sleep(HSECSCAN_RETRY_DELAY_SECONDS)

    last_attempt = attempts[-1] if attempts else {}
    last_rc = int(last_attempt.get("tool_rc") or 1)

    return last_rc, _build_failed_output(url=url, attempts=attempts)


# ==========================================================
# HELPERS DE TEXTO
# ==========================================================

def _clean_text(value: Any) -> str:
    """
    Normaliza texto simple:
    - convierte None en "";
    - elimina saltos de línea;
    - reduce espacios repetidos;
    - conserva el contenido en una sola línea.
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
# ==========================================================
# DETECCIÓN DE ERRORES TÉCNICOS DE HSECSCAN
# ==========================================================

def _extract_http_error(raw_output: str) -> tuple[Optional[int], Optional[str]]:
    """
    Detecta errores HTTP generados por urllib2 dentro de hsecscan.

    Ejemplo:
    urllib2.HTTPError: HTTP Error 403: Forbidden
    """
    raw = raw_output or ""

    match = re.search(
        r"HTTP\s+Error\s+(\d{3})\s*:\s*([^\n\r]+)",
        raw,
        flags=re.IGNORECASE,
    )

    if not match:
        return None, None

    status_code = _safe_int(match.group(1))
    reason = _clean_text(match.group(2))

    return status_code, reason or None


def _detect_hsecscan_tool_error(raw_output: str) -> Dict[str, Any]:
    """
    Detecta si la salida de hsecscan corresponde a un error técnico.

    Casos principales:
    - salida completamente vacía;
    - HTTP Error 403/404/500 u otro error HTTP generado por urllib2;
    - traceback interno de Python;
    - error HTTP interno de urllib2.
    """
    raw = raw_output or ""
    normalized = raw.lower().strip()

    if not normalized:
        return {
            "has_error": True,
            "error_type": "empty_output",
            "error_message": "hsecscan no devolvió salida para analizar.",
            "http_status_code": None,
            "http_reason": None,
        }

    http_status_code, http_reason = _extract_http_error(raw)

    if http_status_code is not None:
        return {
            "has_error": True,
            "error_type": f"http_{http_status_code}",
            "error_message": (
                f"hsecscan no pudo completar la revisión porque el servidor "
                f"respondió HTTP {http_status_code}"
                + (f" {http_reason}" if http_reason else "")
                + "."
            ),
            "http_status_code": http_status_code,
            "http_reason": http_reason,
        }

    if "traceback (most recent call last)" in normalized:
        return {
            "has_error": True,
            "error_type": "python_traceback",
            "error_message": "hsecscan terminó con un traceback interno.",
            "http_status_code": None,
            "http_reason": None,
        }

    if "urllib2.httperror" in normalized:
        return {
            "has_error": True,
            "error_type": "urllib2_http_error",
            "error_message": "hsecscan terminó con un error HTTP interno de urllib2.",
            "http_status_code": None,
            "http_reason": None,
        }

    return {
        "has_error": False,
        "error_type": None,
        "error_message": None,
        "http_status_code": None,
        "http_reason": None,
    }


def _build_parse_warning_for_tool_error(tool_error: Dict[str, Any]) -> Optional[str]:
    """
    Construye una advertencia amigable cuando hsecscan falló técnicamente.
    """
    if not tool_error.get("has_error"):
        return None

    message = tool_error.get("error_message") or "hsecscan devolvió un error técnico."

    if tool_error.get("http_status_code"):
        return (
            f"{message} La verificación principal con curl puede conservarse como "
            "evidencia, pero hsecscan no generó salida estructurada para esta URL."
        )

    return message


# ==========================================================
# PARSEO DE RESPONSE INFO
# ==========================================================

def _parse_response_info(section: str) -> Dict[str, Any]:
    """
    Parsea la sección:

    >> RESPONSE INFO <<

    Devuelve:
    - url;
    - status_code;
    - headers observados como lista, preservando duplicados como Set-Cookie.
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
    - key interna normalizada, por ejemplo "header_name";
    - value del campo.
    """
    if ":" not in line:
        return None, ""

    label, value = _split_first_colon(line)

    key = _FIELD_MAP.get(label)

    if not key:
        return None, ""

    return key, value


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
    Construye un estado amigable para UI.
    """
    record_type = str(record.get("record_type") or "").lower()

    if record_type == "missing":
        return "Faltante"

    return "Observada"


def _finalize_header_record(record: Dict[str, Any], record_type: str) -> Optional[Dict[str, Any]]:
    """
    Normaliza y completa un registro de hsecscan.

    record_type:
    - observed: cabecera presente con detalle de seguridad;
    - missing: cabecera faltante reportada por hsecscan.
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
    tool_error: Optional[Dict[str, Any]] = None,
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

    tool_error = tool_error or {}

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
        "tool_error_type": tool_error.get("error_type"),
        "tool_error_message": tool_error.get("error_message"),
        "tool_http_status_code": tool_error.get("http_status_code"),
        "tool_http_reason": tool_error.get("http_reason"),
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
      "tool_error": {...},
      "response_info": {...},
      "observed_headers": [...],
      "missing_headers": [...],
      "summary": {...},
      "parse_warnings": [...]
    }
    """
    raw = raw_output or ""
    parse_warnings: List[str] = []

    tool_error = _detect_hsecscan_tool_error(raw)
    tool_error_warning = _build_parse_warning_for_tool_error(tool_error)

    if tool_error_warning:
        parse_warnings.append(tool_error_warning)

    response_info_section = _extract_section(raw, "RESPONSE INFO")
    observed_headers_section = _extract_section(raw, "RESPONSE HEADERS DETAILS")
    missing_headers_section = _extract_section(raw, "RESPONSE MISSING HEADERS")

    has_response_info_section = bool(response_info_section)
    has_observed_headers_section = bool(observed_headers_section)
    has_missing_headers_section = bool(missing_headers_section)

    if not has_response_info_section:
        parse_warnings.append("No se encontró la sección RESPONSE INFO.")

    if not has_observed_headers_section:
        parse_warnings.append("No se encontró la sección RESPONSE HEADERS DETAILS.")

    if not has_missing_headers_section:
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
        tool_error=tool_error,
    )

    has_any_expected_section = (
        has_response_info_section
        or has_observed_headers_section
        or has_missing_headers_section
    )

    has_structured_records = bool(observed_headers or missing_headers)
    has_response_headers = bool(response_info.get("headers"))

    # ok=True solo cuando existe salida estructurada real de hsecscan.
    # Un traceback con texto ya no se considera una ejecución parseable.
    ok = (
        not tool_error.get("has_error")
        and has_any_expected_section
        and (has_structured_records or has_response_headers)
    )

    return {
        "ok": ok,
        "tool_error": tool_error,
        "response_info": response_info,
        "observed_headers": observed_headers,
        "missing_headers": missing_headers,
        "summary": summary,
        "parse_warnings": parse_warnings,
    }