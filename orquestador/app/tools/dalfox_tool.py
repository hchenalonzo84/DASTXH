"""
dalfox_tool.py
- CAPA 3: Dalfox (XSS)
- Ejecuta Dalfox contra una URL objetivo y guarda salida JSON.

Esta versión agrega soporte para perfiles de escaneo:
- superficial:
    * ejecución base, menos agresiva
- profundo:
    * agrega mining y análisis DOM más profundo

Objetivo:
- no romper el flujo actual
- permitir que scanner_service decida el perfil
- mantener la normalización de hallazgos para xss_findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import UA
from utils import run_cmd


# ==========================================================
# HELPERS INTERNOS DE PERFIL
# ==========================================================

def _normalize_scan_profile(scan_profile: str | None) -> str:
    """
    Normaliza el perfil recibido.

    Reglas:
    - 'profundo' se respeta
    - cualquier otro valor cae en 'superficial'

    Esto evita problemas si en el futuro llega un valor inesperado
    desde CLI, GUI o API.
    """
    value = (scan_profile or "").strip().lower()
    return "profundo" if value == "profundo" else "superficial"


def _build_profile_args(scan_profile: str) -> List[str]:
    """
    Devuelve flags adicionales de Dalfox según el perfil.

    superficial:
    - sin flags extra agresivos
    - mantiene una ejecución base más conservadora

    profundo:
    - activa descubrimiento de parámetros y análisis DOM más profundo
    - útil para objetivos dinámicos con mayor superficie evaluable
    """
    if scan_profile == "profundo":
        return [
            "--mining-dict",
            "--mining-dom",
            "--deep-domxss",
        ]

    return []


# ==========================================================
# EJECUCIÓN PRINCIPAL DE DALFOX
# ==========================================================

def run_dalfox(
    url: str,
    timeout_s: int,
    out_json: Path,
    scan_profile: str = "superficial",
) -> Tuple[int, str]:
    """
    Ejecuta Dalfox contra una URL y devuelve:
    - código de retorno
    - salida combinada stdout + stderr

    scan_profile controla qué tan profundo será el análisis:
    - superficial -> ejecución base
    - profundo    -> agrega mining + análisis DOM más profundo
    """
    normalized_profile = _normalize_scan_profile(scan_profile)

    cmd = [
        "dalfox", "url", url,
        "--no-color",
        "--no-spinner",
        "--format", "json",
        "-o", str(out_json),
        "--timeout", str(timeout_s),
        "--user-agent", UA,
        "-F",
    ]

    # Agregar flags extra solo si el perfil lo requiere.
    cmd.extend(_build_profile_args(normalized_profile))

    r = run_cmd(cmd)
    raw = (r.out or "") + ("\n" + r.err if r.err else "")
    return r.rc, raw


def read_summary(out_json: Path) -> tuple[int, Any]:
    """
    Lee el archivo JSON de Dalfox y devuelve:
    - findings_count
    - summary_json

    Se mantiene flexible porque Dalfox puede cambiar
    la forma exacta del JSON entre versiones.
    """
    if not out_json.exists():
        return 0, {"_no_json": True}

    try:
        data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0, {"_parse_error": True}

    findings = 0
    if isinstance(data, list):
        findings = len(data)
    elif isinstance(data, dict):
        for k in ("issues", "found", "results", "vulnerabilities", "items", "data"):
            v = data.get(k)
            if isinstance(v, list):
                findings = len(v)
                break

    return findings, data


def _coerce_findings_list(summary_json: Any) -> List[Any]:
    """
    Intenta localizar la lista principal de hallazgos dentro
    de la salida estructurada de Dalfox.

    Casos soportados:
    - summary_json como lista
    - summary_json como dict con alguna clave típica
    - cualquier otro caso -> lista vacía
    """
    if isinstance(summary_json, list):
        return summary_json

    if isinstance(summary_json, dict):
        for key in ("issues", "found", "results", "vulnerabilities", "items", "data"):
            value = summary_json.get(key)
            if isinstance(value, list):
                return value

    return []


def _pick_first_text(source: Dict[str, Any], keys: List[str]) -> str | None:
    """
    Busca la primera clave disponible con contenido textual útil.

    Esto ayuda a adaptarnos a variaciones del JSON de Dalfox
    sin atarnos a un único nombre de propiedad.
    """
    for key in keys:
        value = source.get(key)
        if value is None:
            continue

        text = str(value).strip()
        if text:
            return text

    return None


def extract_structured_findings(
    summary_json: Any,
    fallback_target_url: str | None = None,
) -> List[Dict[str, Any]]:
    """
    Convierte la salida estructurada de Dalfox en una lista de hallazgos
    normalizados para persistencia en la tabla xss_findings.

    Campos que intentamos extraer:
    - finding_order
    - source_type
    - target_url
    - param_name
    - payload
    - evidence
    - severity
    - raw_finding_json

    Nota:
    como la forma exacta del JSON puede variar, usamos extracción
    tolerante y dejamos raw_finding_json como respaldo completo.
    """
    raw_findings = _coerce_findings_list(summary_json)
    normalized: List[Dict[str, Any]] = []

    for idx, item in enumerate(raw_findings, start=1):
        if isinstance(item, dict):
            source_type = _pick_first_text(item, ["type", "source", "kind", "category"])
            target_url = _pick_first_text(item, ["url", "target", "target_url"]) or fallback_target_url
            param_name = _pick_first_text(item, ["param", "parameter", "param_name", "key"])
            payload = _pick_first_text(item, ["payload", "poc", "proof", "vector", "inject"])
            evidence = _pick_first_text(item, ["evidence", "message", "detail", "trigger", "proof"])
            severity = _pick_first_text(item, ["severity", "risk", "priority", "level"])
            raw_finding_json = item
        else:
            source_type = None
            target_url = fallback_target_url
            param_name = None
            payload = str(item).strip() or None
            evidence = str(item).strip() or None
            severity = None
            raw_finding_json = {"value": item}

        normalized.append(
            {
                "finding_order": idx,
                "source_type": source_type,
                "target_url": target_url,
                "param_name": param_name,
                "payload": payload,
                "evidence": evidence,
                "severity": severity,
                "raw_finding_json": raw_finding_json,
            }
        )

    return normalized