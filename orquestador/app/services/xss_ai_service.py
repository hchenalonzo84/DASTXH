"""
xss_ai_service.py
- Prepara hallazgos XSS para interpretación con IA.
- La agrupación NO se muestra como sección separada en la GUI.
- La agrupación solo se usa internamente cuando hace falta.

Reglas acordadas:
- hasta 10 hallazgos válidos  -> modo individual
- más de 10                   -> agrupar
- más de 50                   -> agrupar sí o sí
- más de 100                  -> agrupar y recortar ejemplos representativos

Cambios importantes:
- Filtra hallazgos vacíos o no útiles antes de preparar entradas para IA.
- Evita crear grupos Unknown/payload_desconocido sin payload ni evidencia.
- Recorta evidencia desde la preparación para no enviar bloques enormes al modelo.
- Conserva total_findings como conteo original de Dalfox, pero agrega conteos útiles:
  total_valid_findings y excluded_findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse


# ==========================================================
# CONSTANTES DE PREPARACIÓN
# ==========================================================

# La evidencia de Dalfox puede traer muchas líneas repetidas de paginación,
# filtros, opciones de ordenamiento, etc. Esta longitud es suficiente para
# que la IA identifique el patrón sin saturar el prompt.
MAX_EVIDENCE_CHARS_IN_PREPARATION = 700

# Payloads muy largos también se recortan para evitar ruido.
MAX_PAYLOAD_CHARS_IN_PREPARATION = 350

# Cuando se trabaja en modo agrupado, solo se guardan muestras representativas.
DEFAULT_GROUP_SAMPLE_ORDERS = 5
DEFAULT_GROUP_SAMPLE_PAYLOADS = 3
DEFAULT_GROUP_SAMPLE_EVIDENCE = 3


# ==========================================================
# HELPERS DE TEXTO
# ==========================================================

def _normalize_text(value: Any) -> str:
    """
    Limpia texto para comparaciones internas.
    """
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _truncate_text(value: Any, max_chars: int) -> str:
    """
    Recorta texto largo conservando una señal clara de truncamiento.
    """
    text = _normalize_text(value)

    if max_chars <= 0:
        return text

    if len(text) <= max_chars:
        return text

    return text[:max_chars].rstrip() + "..."


def _unique_preserve_order(items: List[str]) -> List[str]:
    """
    Elimina duplicados sin perder el orden original.
    """
    seen = set()
    result: List[str] = []

    for item in items:
        value = _normalize_text(item)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def _unique_limited_preserve_order(
    items: List[str],
    max_items: int,
    max_chars: int,
) -> List[str]:
    """
    Elimina duplicados, recorta textos largos y limita la cantidad de ejemplos.
    """
    result: List[str] = []
    seen = set()

    for item in items:
        value = _truncate_text(item, max_chars=max_chars)

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

        if len(result) >= max_items:
            break

    return result


def _safe_int(value: Any, default: int = 0) -> int:
    """
    Convierte a entero sin romper el flujo.
    """
    try:
        return int(value or default)
    except Exception:
        return default


# ==========================================================
# VALIDACIÓN DE HALLAZGOS
# ==========================================================

def _has_textual_payload_or_evidence(finding: Dict[str, Any]) -> bool:
    """
    Verifica si el hallazgo tiene al menos payload o evidencia útil.
    """
    payload = _normalize_text(finding.get("payload"))
    evidence = _normalize_text(finding.get("evidence"))

    return bool(payload or evidence)


def _is_unknown_or_empty_finding(finding: Dict[str, Any]) -> bool:
    """
    Detecta hallazgos que no aportan una señal XSS útil.

    Caso típico observado:
    - payload vacío
    - evidence vacío
    - severity Unknown
    - param_name vacío o '-'

    Estos hallazgos generaban filas con '-' y luego interpretaciones falsas.
    """
    payload = _normalize_text(finding.get("payload"))
    evidence = _normalize_text(finding.get("evidence"))
    severity = _normalize_text(finding.get("severity")).lower()
    param_name = _normalize_text(finding.get("param_name")).lower()

    has_payload = bool(payload and payload != "-")
    has_evidence = bool(evidence and evidence != "-")

    severity_unknown = severity in ("", "-", "unknown", "desconocido")
    param_unknown = param_name in ("", "-", "unknown", "desconocido")

    return not has_payload and not has_evidence and severity_unknown and param_unknown


def _is_valid_xss_finding(finding: Dict[str, Any]) -> bool:
    """
    Decide si un hallazgo debe participar en la preparación para IA.

    No intenta confirmar explotabilidad real; solo evita pasar entradas vacías,
    sin payload y sin evidencia, que no sirven para interpretación.
    """
    if not isinstance(finding, dict):
        return False

    if _is_unknown_or_empty_finding(finding):
        return False

    if not _has_textual_payload_or_evidence(finding):
        return False

    return True


def _filter_valid_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filtra hallazgos no útiles.

    Regla acordada:
    - Si hay hallazgos válidos, se excluyen los vacíos/Unknown.
    - Si no hay hallazgos válidos, se devuelve lista vacía. No se fuerza una
      interpretación artificial de algo que no tiene evidencia.
    """
    valid_findings: List[Dict[str, Any]] = []

    for finding in findings:
        if _is_valid_xss_finding(finding):
            valid_findings.append(finding)

    return valid_findings


# ==========================================================
# INFERENCIA DE PARÁMETRO / CONTEXTO / FIRMA
# ==========================================================

def _infer_parameter_probable(finding: Dict[str, Any]) -> str:
    """
    Intenta obtener el parámetro más probable.
    """
    param_name = _normalize_text(finding.get("param_name"))

    if param_name and param_name != "-":
        return param_name

    target_url = _normalize_text(finding.get("target_url"))

    if target_url:
        parsed = urlparse(target_url)
        query_map = parse_qs(parsed.query)
        query_keys = list(query_map.keys())

        if len(query_keys) == 1:
            return query_keys[0]

    evidence = _normalize_text(finding.get("evidence")).lower()

    # Patrones frecuentes de query strings reflejadas.
    for candidate in [
        "q",
        "search",
        "s",
        "query",
        "term",
        "page",
        "limit",
        "sort",
        "filter",
        "description",
        "coupon",
    ]:
        if f"{candidate}=" in evidence or f"{candidate}&" in evidence:
            return candidate

    return "desconocido"


def _infer_context_probable(finding: Dict[str, Any]) -> str:
    """
    Clasifica el contexto HTML más probable de la reflexión.
    """
    evidence = _normalize_text(finding.get("evidence")).lower()
    payload = _normalize_text(finding.get("payload")).lower()

    combined = f"{evidence} {payload}"

    # Enlaces HTML.
    if "<a" in combined or "href" in combined or "rel=" in combined:
        return "enlaces HTML"

    # Formularios / inputs.
    if "<form" in combined or "<input" in combined or "<textarea" in combined or "<select" in combined:
        return "formularios"

    # Opciones de listado o combos.
    if "<option" in combined or "selected=" in combined:
        return "opciones de listado"

    # Paginación, filtros y ordenamientos.
    if "page=" in combined or "limit=" in combined or "sort=" in combined or "filter" in combined:
        return "paginación o filtros"

    # HTML reflejado general.
    return "html reflejado general"


def _infer_payload_signature(finding: Dict[str, Any]) -> str:
    """
    Resume el tipo de carga útil para agrupar patrones similares.
    """
    payload = _normalize_text(finding.get("payload")).lower()

    if not payload:
        return "payload_desconocido"

    if "javascript:alert" in payload and "href" in payload:
        return "javascript_uri_en_href"

    if "onload=" in payload:
        return "event_handler_onload"

    if "onerror=" in payload:
        return "event_handler_onerror"

    if (
        "onmouseover=" in payload
        or "onmouseenter=" in payload
        or "onmouseleave=" in payload
        or "onpointerleave=" in payload
        or "onpointerenter=" in payload
        or "onpointerover=" in payload
        or "onpointerup=" in payload
        or "onpointerdown=" in payload
        or "ontouchmove=" in payload
        or "ontouchstart=" in payload
        or "ontouchend=" in payload
    ):
        return "event_handler_mouse"

    if "<svg" in payload:
        return "svg_injection"

    if "<img" in payload:
        return "img_injection"

    if "<script" in payload:
        return "script_tag_injection"

    if "<base" in payload:
        return "base_tag_injection"

    if "<object" in payload:
        return "object_tag_injection"

    if "<embed" in payload:
        return "embed_tag_injection"

    if "<video" in payload or "<source" in payload:
        return "media_tag_injection"

    if "<textarea" in payload:
        return "textarea_injection"

    if "alert(" in payload or "confirm(" in payload or "prompt(" in payload:
        return "js_execution_probe"

    if "alert.call(" in payload or "alert.apply(" in payload:
        return "js_execution_probe"

    if "confirm.call(" in payload or "confirm.apply(" in payload:
        return "js_execution_probe"

    if "prompt.call(" in payload or "prompt.apply(" in payload:
        return "js_execution_probe"

    return "payload_html_reflejado"


# ==========================================================
# CONSTRUCCIÓN DE ENTRADAS
# ==========================================================

def _build_individual_entry(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Crea una entrada individual. Se usa cuando el volumen válido es pequeño.
    """
    finding_order = _safe_int(finding.get("finding_order"), default=0)
    payload = _truncate_text(finding.get("payload"), MAX_PAYLOAD_CHARS_IN_PREPARATION)
    evidence = _truncate_text(finding.get("evidence"), MAX_EVIDENCE_CHARS_IN_PREPARATION)

    return {
        # IMPORTANTE:
        # group_order se asigna después de construir la lista completa.
        "group_order": None,
        "entry_type": "individual",
        "parameter_probable": _infer_parameter_probable(finding),
        "context_probable": _infer_context_probable(finding),
        "severity_mode": _normalize_text(finding.get("severity")) or "Unknown",
        "payload_signature": _infer_payload_signature(finding),
        "occurrences": 1,
        "target_url": _normalize_text(finding.get("target_url")),
        # Todos los finding_orders que representa esta entrada.
        "finding_orders": [finding_order] if finding_order > 0 else [],
        # Ejemplos que luego verá la IA.
        "sample_finding_orders": [finding_order] if finding_order > 0 else [],
        "sample_payloads": [payload] if payload else [],
        "sample_evidence": [evidence] if evidence else [],
    }


def _build_grouped_entries(findings: List[Dict[str, Any]], trim_examples: bool) -> List[Dict[str, Any]]:
    """
    Agrupa hallazgos similares para reducir ruido antes de enviarlos al modelo.
    """
    grouped: Dict[tuple, Dict[str, Any]] = {}

    for finding in findings:
        parameter_probable = _infer_parameter_probable(finding)
        context_probable = _infer_context_probable(finding)
        severity_mode = _normalize_text(finding.get("severity")) or "Unknown"
        payload_signature = _infer_payload_signature(finding)
        target_url = _normalize_text(finding.get("target_url"))

        # Si después del filtrado todavía llegara una entrada sin señal útil,
        # no se agrupa. Es una segunda defensa.
        if (
            severity_mode.lower() in ("", "-", "unknown", "desconocido")
            and payload_signature == "payload_desconocido"
            and not _has_textual_payload_or_evidence(finding)
        ):
            continue

        key = (
            parameter_probable,
            context_probable,
            severity_mode,
            payload_signature,
        )

        if key not in grouped:
            grouped[key] = {
                # IMPORTANTE:
                # group_order se asigna después del sort final.
                "group_order": None,
                "entry_type": "group",
                "parameter_probable": parameter_probable,
                "context_probable": context_probable,
                "severity_mode": severity_mode,
                "payload_signature": payload_signature,
                "occurrences": 0,
                "target_url": target_url,
                "finding_orders": [],
                "sample_finding_orders": [],
                "sample_payloads": [],
                "sample_evidence": [],
            }

        entry = grouped[key]
        entry["occurrences"] += 1

        finding_order = _safe_int(finding.get("finding_order"), default=0)
        payload = _truncate_text(finding.get("payload"), MAX_PAYLOAD_CHARS_IN_PREPARATION)
        evidence = _truncate_text(finding.get("evidence"), MAX_EVIDENCE_CHARS_IN_PREPARATION)

        if finding_order > 0:
            entry["finding_orders"].append(finding_order)
            entry["sample_finding_orders"].append(finding_order)

        if payload:
            entry["sample_payloads"].append(payload)

        if evidence:
            entry["sample_evidence"].append(evidence)

    entries = list(grouped.values())

    # Normalización final y recorte representativo.
    for entry in entries:
        entry["finding_orders"] = sorted(set(entry["finding_orders"]))
        entry["sample_finding_orders"] = sorted(set(entry["sample_finding_orders"]))

        # En modo agrupado, aunque trim_examples sea False, no conviene guardar
        # decenas de payloads/evidencias en xss_ai_groups porque luego eso
        # vuelve pesada la GUI y la llamada a IA.
        sample_orders_limit = DEFAULT_GROUP_SAMPLE_ORDERS
        sample_payloads_limit = DEFAULT_GROUP_SAMPLE_PAYLOADS
        sample_evidence_limit = DEFAULT_GROUP_SAMPLE_EVIDENCE

        if trim_examples:
            sample_orders_limit = 5
            sample_payloads_limit = 3
            sample_evidence_limit = 3

        entry["sample_finding_orders"] = entry["sample_finding_orders"][:sample_orders_limit]

        entry["sample_payloads"] = _unique_limited_preserve_order(
            entry["sample_payloads"],
            max_items=sample_payloads_limit,
            max_chars=MAX_PAYLOAD_CHARS_IN_PREPARATION,
        )

        entry["sample_evidence"] = _unique_limited_preserve_order(
            entry["sample_evidence"],
            max_items=sample_evidence_limit,
            max_chars=MAX_EVIDENCE_CHARS_IN_PREPARATION,
        )

    # Orden estable: primero grupos con más ocurrencias.
    entries.sort(
        key=lambda x: (
            -int(x.get("occurrences", 0) or 0),
            str(x.get("parameter_probable") or ""),
            str(x.get("context_probable") or ""),
            str(x.get("severity_mode") or ""),
            str(x.get("payload_signature") or ""),
        )
    )

    return entries


def _assign_group_order(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Asigna group_order secuencial y estable a todas las entradas.

    Esto es CLAVE para que la interpretación IA se pueda amarrar
    correctamente a lo que luego se persiste y se muestra.
    """
    result: List[Dict[str, Any]] = []

    for index, raw_item in enumerate(entries, start=1):
        item = dict(raw_item)
        item["group_order"] = index
        result.append(item)

    return result


# ==========================================================
# API PÚBLICA
# ==========================================================

def build_xss_ai_input_payload(structured_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Construye la carga base para interpretación XSS con IA.

    Reglas acordadas:
    - hasta 10 hallazgos válidos  -> individuales
    - más de 10                   -> agrupados
    - más de 50                   -> agrupados obligatoriamente
    - más de 100                  -> agrupados + recorte de ejemplos

    Nota:
    total_findings conserva el conteo original de Dalfox/BD.
    total_valid_findings indica cuántos hallazgos sí se usaron para IA.
    excluded_findings indica cuántos se omitieron por estar vacíos/no útiles.
    """
    raw_findings = structured_findings or []
    total_findings = len(raw_findings)

    if total_findings == 0:
        return {
            "mode": "empty",
            "total_findings": 0,
            "total_valid_findings": 0,
            "excluded_findings": 0,
            "total_groups": 0,
            "entries": [],
        }

    valid_findings = _filter_valid_findings(raw_findings)
    total_valid_findings = len(valid_findings)
    excluded_findings = total_findings - total_valid_findings

    if total_valid_findings == 0:
        return {
            "mode": "empty_or_unreliable",
            "total_findings": total_findings,
            "total_valid_findings": 0,
            "excluded_findings": excluded_findings,
            "total_groups": 0,
            "entries": [],
        }

    # Hasta 10 hallazgos válidos: mantener granularidad por hallazgo.
    if total_valid_findings <= 10:
        entries = [_build_individual_entry(item) for item in valid_findings]
        entries = _assign_group_order(entries)

        return {
            "mode": "individual",
            "total_findings": total_findings,
            "total_valid_findings": total_valid_findings,
            "excluded_findings": excluded_findings,
            "total_groups": len(entries),
            "entries": entries,
        }

    # Más de 10 hallazgos válidos: agrupar.
    trim_examples = total_valid_findings > 100
    entries = _build_grouped_entries(valid_findings, trim_examples=trim_examples)
    entries = _assign_group_order(entries)

    return {
        "mode": "grouped",
        "total_findings": total_findings,
        "total_valid_findings": total_valid_findings,
        "excluded_findings": excluded_findings,
        "total_groups": len(entries),
        "entries": entries,
    }