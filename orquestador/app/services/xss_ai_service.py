"""
xss_ai_service.py
- Prepara hallazgos XSS para interpretación con IA.
- La agrupación NO se muestra como sección separada en la GUI.
- La agrupación solo se usa internamente cuando hace falta.

Reglas acordadas:
- hasta 10 hallazgos  -> modo individual
- más de 10           -> agrupar
- más de 50           -> agrupar sí o sí
- más de 100          -> agrupar y recortar ejemplos representativos
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse


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
    for candidate in ["q", "search", "s", "query", "term", "page", "limit", "sort", "filter", "description"]:
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

    if "onmouseover=" in payload or "onmouseenter=" in payload or "onmouseleave=" in payload or "onpointerleave=" in payload:
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

    if "<textarea" in payload:
        return "textarea_injection"

    if "alert(" in payload or "confirm(" in payload or "prompt(" in payload or "alert.call(" in payload or "alert.apply(" in payload:
        return "js_execution_probe"

    return "payload_html_reflejado"


# ==========================================================
# CONSTRUCCIÓN DE ENTRADAS
# ==========================================================

def _build_individual_entry(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Crea una entrada individual. Se usa cuando el volumen es pequeño.
    """
    finding_order = int(finding.get("finding_order", 0) or 0)
    payload = _normalize_text(finding.get("payload"))
    evidence = _normalize_text(finding.get("evidence"))

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

        finding_order = int(finding.get("finding_order", 0) or 0)
        payload = _normalize_text(finding.get("payload"))
        evidence = _normalize_text(finding.get("evidence"))

        if finding_order > 0:
            entry["finding_orders"].append(finding_order)
            entry["sample_finding_orders"].append(finding_order)

        if payload:
            entry["sample_payloads"].append(payload)

        if evidence:
            entry["sample_evidence"].append(evidence)

    entries = list(grouped.values())

    # Normalización final y recorte representativo cuando el volumen es muy grande.
    for entry in entries:
        entry["finding_orders"] = sorted(set(entry["finding_orders"]))
        entry["sample_finding_orders"] = sorted(set(entry["sample_finding_orders"]))
        entry["sample_payloads"] = _unique_preserve_order(entry["sample_payloads"])
        entry["sample_evidence"] = _unique_preserve_order(entry["sample_evidence"])

        if trim_examples:
            entry["sample_finding_orders"] = entry["sample_finding_orders"][:5]
            entry["sample_payloads"] = entry["sample_payloads"][:3]
            entry["sample_evidence"] = entry["sample_evidence"][:3]

    # Orden estable: primero grupos con más ocurrencias.
    entries.sort(
        key=lambda x: (
            -int(x.get("occurrences", 0) or 0),
            str(x.get("parameter_probable") or ""),
            str(x.get("context_probable") or ""),
            str(x.get("severity_mode") or ""),
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
    - hasta 10 hallazgos  -> individuales
    - más de 10           -> agrupados
    - más de 50           -> agrupados obligatoriamente
    - más de 100          -> agrupados + recorte de ejemplos
    """
    findings = structured_findings or []
    total_findings = len(findings)

    if total_findings == 0:
        return {
            "mode": "empty",
            "total_findings": 0,
            "total_groups": 0,
            "entries": [],
        }

    # Hasta 10: mantener granularidad por hallazgo.
    if total_findings <= 10:
        entries = [_build_individual_entry(item) for item in findings]
        entries = _assign_group_order(entries)

        return {
            "mode": "individual",
            "total_findings": total_findings,
            "total_groups": len(entries),
            "entries": entries,
        }

    # Más de 10: agrupar.
    trim_examples = total_findings > 100
    entries = _build_grouped_entries(findings, trim_examples=trim_examples)
    entries = _assign_group_order(entries)

    return {
        "mode": "grouped",
        "total_findings": total_findings,
        "total_groups": len(entries),
        "entries": entries,
    }