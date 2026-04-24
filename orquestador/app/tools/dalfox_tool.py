"""
dalfox_tool.py
- CAPA XSS: Dalfox
- Ejecuta Dalfox en modo url y normaliza hallazgos.

Objetivos de esta versión:
- soportar scan_profile superficial/profundo
- reducir tiempo en perfil superficial
- filtrar hallazgos vacíos o basura
- entregar datos más útiles para la GUI
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import UA
from utils import run_cmd


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

    Reglas por perfil:
    - superficial:
        * más rápido
        * sin parameter mining
    - profundo:
        * mantiene comportamiento más completo
    """
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

    # ------------------------------------------------------
    # Perfil superficial:
    # - evita minería extra de parámetros para acelerar
    # ------------------------------------------------------
    if scan_profile == "superficial":
        cmd.extend(["--skip-mining-all"])

    # ------------------------------------------------------
    # Perfil profundo:
    # - dejamos el comportamiento estándar de Dalfox
    # ------------------------------------------------------

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
    """
    for key in keys:
        value = source.get(key)
        if value is None:
            continue

        text = str(value).strip()
        if text:
            return text

    return None


def _normalize_optional_text(value: Any) -> str | None:
    """
    Convierte un valor a texto útil o None si queda vacío.
    """
    if value is None:
        return None

    text = str(value).strip()
    return text if text else None


def _has_meaningful_content(
    param_name: str | None,
    payload: str | None,
    evidence: str | None,
    severity: str | None,
    target_url: str | None,
) -> bool:
    """
    Evita guardar hallazgos completamente vacíos que luego
    aparecen en la GUI como filas de guiones.
    """
    return any(
        value is not None and str(value).strip()
        for value in (param_name, payload, evidence, severity, target_url)
    )


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
    """
    raw_findings = _coerce_findings_list(summary_json)
    normalized: List[Dict[str, Any]] = []
    finding_order = 0

    for item in raw_findings:
        if isinstance(item, dict):
            source_type = _pick_first_text(item, ["type", "source", "kind", "category"])
            target_url = _pick_first_text(item, ["url", "target", "target_url"]) or fallback_target_url
            param_name = _pick_first_text(item, ["param", "parameter", "param_name", "key"])
            payload = _pick_first_text(item, ["payload", "poc", "proof", "vector", "inject"])
            evidence = _pick_first_text(item, ["evidence", "message", "detail", "trigger", "reflected"])
            severity = _pick_first_text(item, ["severity", "risk", "priority", "level"])
            raw_finding_json = item
        else:
            source_type = None
            target_url = fallback_target_url
            param_name = None
            payload = _normalize_optional_text(item)
            evidence = _normalize_optional_text(item)
            severity = None
            raw_finding_json = {"value": item}

        source_type = _normalize_optional_text(source_type)
        target_url = _normalize_optional_text(target_url)
        param_name = _normalize_optional_text(param_name)
        payload = _normalize_optional_text(payload)
        evidence = _normalize_optional_text(evidence)
        severity = _normalize_optional_text(severity)

        # --------------------------------------------------
        # Si el hallazgo viene vacío, no lo persistimos
        # --------------------------------------------------
        if not _has_meaningful_content(
            param_name=param_name,
            payload=payload,
            evidence=evidence,
            severity=severity,
            target_url=target_url,
        ):
            continue

        finding_order += 1

        normalized.append(
            {
                "finding_order": finding_order,
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