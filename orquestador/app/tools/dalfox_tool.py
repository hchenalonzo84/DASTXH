"""
dalfox_tool.py
- Wrapper de ejecución de Dalfox para DASTXH.

Objetivo:
- Ejecutar Dalfox de forma controlada dentro del flujo DASTXH.
- Generar evidencia JSON para persistencia estructurada.
- Generar evidencia TXT para revisión técnica.
- Activar soporte DOM XSS mediante:
    --deep-domxss
    --force-headless-verification
- Normalizar hallazgos headless/DOM XSS sin llenar la tabla con URLs largas.

Regla visual importante:
- Parámetro debe mostrar el nombre del parámetro afectado.
- Payload debe mostrar solo el valor inyectado, no la URL completa.
- Evidencia debe mostrar una confirmación entendible para el usuario.
- La URL explotada completa se conserva como poc_url/request_url para trazabilidad,
  pero no se usa como payload ni como evidencia principal.

Compatibilidad:
- scanner_service.py espera estas funciones:
    run_dalfox(...)
    read_summary(...)
    extract_structured_findings(...)
"""

from __future__ import annotations

import json
import os
import subprocess
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus, urlsplit

import config


# ==========================================================
# CONSTANTES
# ==========================================================

DALFOX_SOURCE_NAME = "dalfox"
DALFOX_TIMEOUT_EXIT_CODE = 124


# ==========================================================
# HELPERS DE CONFIGURACIÓN
# ==========================================================

def _env_to_bool(value: Any, default: bool = False) -> bool:
    """
    Convierte valores de entorno a booleano.

    Acepta:
    - true / false
    - 1 / 0
    - yes / no
    - on / off
    - si / no
    """
    if value is None:
        return default

    text = str(value).strip().lower()

    if text in {"1", "true", "yes", "y", "on", "si", "sí"}:
        return True

    if text in {"0", "false", "no", "n", "off"}:
        return False

    return default


def _get_config_int(
    env_name: str,
    config_attr: str,
    default: int,
) -> int:
    """
    Lee un entero desde variable de entorno o desde config.py.
    """
    raw_value = os.getenv(env_name)

    if raw_value is None:
        raw_value = getattr(config, config_attr, default)

    try:
        value = int(raw_value)
    except Exception:
        value = default

    if value <= 0:
        return default

    return value


def _get_config_bool(
    env_name: str,
    config_attr: str,
    default: bool,
) -> bool:
    """
    Lee un booleano desde variable de entorno o desde config.py.
    """
    if env_name in os.environ:
        return _env_to_bool(os.getenv(env_name), default=default)

    return bool(getattr(config, config_attr, default))


def _get_dalfox_request_timeout(timeout_s: Optional[int]) -> int:
    """
    Calcula el timeout por solicitud para Dalfox.

    Regla:
    - Se usa DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS/config.py.
    - Si el flujo trae un timeout menor, se respeta el menor.
    """
    configured_timeout = _get_config_int(
        env_name="DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS",
        config_attr="DALFOX_REQUEST_TIMEOUT_SECONDS",
        default=25,
    )

    if timeout_s is None or timeout_s <= 0:
        return configured_timeout

    return max(1, min(configured_timeout, int(timeout_s)))


def _get_dalfox_hard_timeout() -> int:
    """
    Obtiene el timeout duro del proceso completo de Dalfox.
    """
    return _get_config_int(
        env_name="DASTXH_DALFOX_HARD_TIMEOUT_SECONDS",
        config_attr="DALFOX_HARD_TIMEOUT_SECONDS",
        default=420,
    )


def _get_dalfox_workers() -> int:
    """
    Obtiene la cantidad de workers de Dalfox.
    """
    return _get_config_int(
        env_name="DASTXH_DALFOX_WORKERS",
        config_attr="DALFOX_WORKERS",
        default=6,
    )


def _is_light_mining_enabled() -> bool:
    """
    Indica si la minería ligera de Dalfox está habilitada.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_LIGHT_MINING_ENABLED",
        config_attr="DALFOX_LIGHT_MINING_ENABLED",
        default=True,
    )


def _should_skip_mining_dom() -> bool:
    """
    Indica si Dalfox debe omitir minería DOM.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_SKIP_MINING_DOM",
        config_attr="DALFOX_SKIP_MINING_DOM",
        default=False,
    )


def _should_skip_mining_dict() -> bool:
    """
    Indica si Dalfox debe omitir minería por diccionario.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_SKIP_MINING_DICT",
        config_attr="DALFOX_SKIP_MINING_DICT",
        default=False,
    )


def _is_deep_domxss_enabled() -> bool:
    """
    Indica si debe agregarse --deep-domxss.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_DEEP_DOMXSS_ENABLED",
        config_attr="DALFOX_DEEP_DOMXSS_ENABLED",
        default=True,
    )


def _is_force_headless_verification_enabled() -> bool:
    """
    Indica si debe agregarse --force-headless-verification.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_FORCE_HEADLESS_VERIFICATION",
        config_attr="DALFOX_FORCE_HEADLESS_VERIFICATION",
        default=True,
    )


# ==========================================================
# HELPERS DE JSON
# ==========================================================

def _write_json_file(path: Path, payload: Any) -> None:
    """
    Escribe JSON con formato legible.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
        errors="replace",
    )


def _read_json_file(path: Path) -> Any:
    """
    Lee JSON desde disco.

    Si no puede leerlo, devuelve un objeto estructurado de error.
    """
    try:
        if not path.exists() or not path.is_file():
            return {
                "ok": False,
                "error": "El archivo JSON de Dalfox no existe.",
                "findings": [],
            }

        raw = path.read_text(encoding="utf-8", errors="replace").strip()

        if not raw:
            return {
                "ok": False,
                "error": "El archivo JSON de Dalfox está vacío.",
                "findings": [],
            }

        return json.loads(raw)

    except Exception as exc:
        return {
            "ok": False,
            "error": f"No fue posible leer el JSON de Dalfox: {str(exc)}",
            "findings": [],
        }


def _is_valid_json_file(path: Path) -> bool:
    """
    Verifica si el archivo existe y contiene JSON válido.
    """
    try:
        if not path.exists() or not path.is_file():
            return False

        raw = path.read_text(encoding="utf-8", errors="replace").strip()

        if not raw:
            return False

        json.loads(raw)
        return True

    except Exception:
        return False


def _write_fallback_dalfox_json(
    out_json: Path,
    target_url: str,
    tool_rc: int,
    raw_output: str,
    error: Optional[str] = None,
) -> None:
    """
    Crea un JSON mínimo si Dalfox no generó salida JSON válida.
    """
    payload = {
        "ok": False,
        "tool": DALFOX_SOURCE_NAME,
        "target_url": target_url,
        "tool_rc": tool_rc,
        "error": error,
        "raw_output_preview": (raw_output or "")[:4000],
        "findings": [],
    }

    _write_json_file(out_json, payload)


# ==========================================================
# COMANDO DALFOX
# ==========================================================

def _build_dalfox_command(
    url: str,
    out_json: Path,
    timeout_s: Optional[int],
    scan_profile: Optional[str],
) -> List[str]:
    """
    Construye el comando final de Dalfox.

    Aquí se agregan realmente:
    - --deep-domxss
    - --force-headless-verification
    """
    request_timeout = _get_dalfox_request_timeout(timeout_s)
    workers = _get_dalfox_workers()

    cmd: List[str] = [
        "dalfox",
        "url",
        url,
        "--format",
        "json",
        "--output",
        str(out_json),
        "--timeout",
        str(request_timeout),
        "--worker",
        str(workers),
    ]

    if not _is_light_mining_enabled():
        cmd.append("--skip-mining-dom")
        cmd.append("--skip-mining-dict")
    else:
        if _should_skip_mining_dom():
            cmd.append("--skip-mining-dom")

        if _should_skip_mining_dict():
            cmd.append("--skip-mining-dict")

    if _is_deep_domxss_enabled():
        cmd.append("--deep-domxss")

    if _is_force_headless_verification_enabled():
        cmd.append("--force-headless-verification")

    return cmd


def _build_dalfox_runtime_env() -> Dict[str, str]:
    """
    Construye el entorno para ejecutar Dalfox.
    """
    env = dict(os.environ)

    env.setdefault("CHROME_BIN", "/usr/bin/chromium")
    env.setdefault("CHROMIUM_BIN", "/usr/bin/chromium")

    return env


def _build_config_log_line(
    request_timeout: int,
    hard_timeout: int,
    workers: int,
) -> str:
    """
    Construye una línea de log con la configuración efectiva de Dalfox.
    """
    return (
        "[DASTXH] Configuración Dalfox aplicada: "
        f"request_timeout={request_timeout}s, "
        f"hard_timeout={hard_timeout}s, "
        f"workers={workers}, "
        f"light_mining_enabled={_is_light_mining_enabled()}, "
        f"skip_mining_dom={_should_skip_mining_dom()}, "
        f"skip_mining_dict={_should_skip_mining_dict()}, "
        f"deep_domxss_enabled={_is_deep_domxss_enabled()}, "
        f"force_headless_verification={_is_force_headless_verification_enabled()}, "
        "flow=evaluacion_profunda_controlada"
    )


def run_dalfox(
    url: str,
    timeout_s: int,
    out_json: Path,
    scan_profile: str = "profundo",
) -> Tuple[int, str]:
    """
    Ejecuta Dalfox y devuelve:

    - código de salida;
    - salida textual para dalfox.txt.
    """
    out_json = Path(out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    try:
        if out_json.exists():
            out_json.unlink()
    except Exception:
        pass

    request_timeout = _get_dalfox_request_timeout(timeout_s)
    hard_timeout = _get_dalfox_hard_timeout()
    workers = _get_dalfox_workers()

    cmd = _build_dalfox_command(
        url=url,
        out_json=out_json,
        timeout_s=timeout_s,
        scan_profile=scan_profile,
    )

    command_for_log = " ".join(cmd)

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=hard_timeout,
            env=_build_dalfox_runtime_env(),
            check=False,
        )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        raw_output = (
            f"{_build_config_log_line(request_timeout, hard_timeout, workers)}\n"
            f"[DASTXH] Dalfox command\n"
            f"{command_for_log}\n\n"
            "[DASTXH] Dalfox stdout\n"
            f"{stdout}\n\n"
            "[DASTXH] Dalfox stderr\n"
            f"{stderr}\n"
        )

        if not _is_valid_json_file(out_json):
            _write_fallback_dalfox_json(
                out_json=out_json,
                target_url=url,
                tool_rc=completed.returncode,
                raw_output=raw_output,
                error="Dalfox no generó un JSON válido.",
            )

        return completed.returncode, raw_output

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        raw_output = (
            f"{_build_config_log_line(request_timeout, hard_timeout, workers)}\n"
            f"[DASTXH] Dalfox command\n"
            f"{command_for_log}\n\n"
            "[DASTXH] Dalfox timeout\n"
            f"Dalfox superó el límite duro de {hard_timeout} segundos.\n\n"
            "[DASTXH] stdout parcial\n"
            f"{stdout}\n\n"
            "[DASTXH] stderr parcial\n"
            f"{stderr}\n"
        )

        if not _is_valid_json_file(out_json):
            _write_fallback_dalfox_json(
                out_json=out_json,
                target_url=url,
                tool_rc=DALFOX_TIMEOUT_EXIT_CODE,
                raw_output=raw_output,
                error=f"Dalfox superó el timeout duro de {hard_timeout} segundos.",
            )

        return DALFOX_TIMEOUT_EXIT_CODE, raw_output

    except Exception as exc:
        raw_output = (
            f"{_build_config_log_line(request_timeout, hard_timeout, workers)}\n"
            f"[DASTXH] Dalfox command\n"
            f"{command_for_log}\n\n"
            "[DASTXH] Error ejecutando Dalfox\n"
            f"{str(exc)}\n\n"
            "[DASTXH] Traceback\n"
            f"{traceback.format_exc()}\n"
        )

        if not _is_valid_json_file(out_json):
            _write_fallback_dalfox_json(
                out_json=out_json,
                target_url=url,
                tool_rc=1,
                raw_output=raw_output,
                error=str(exc),
            )

        return 1, raw_output


# ==========================================================
# LECTURA DE RESUMEN
# ==========================================================

def _extract_findings_container(summary_json: Any) -> List[Any]:
    """
    Extrae la lista de hallazgos desde posibles formatos JSON de Dalfox.
    """
    if summary_json is None:
        return []

    if isinstance(summary_json, list):
        return summary_json

    if not isinstance(summary_json, dict):
        return []

    candidate_keys = [
        "findings",
        "results",
        "result",
        "data",
        "pocs",
        "poc",
        "vulnerabilities",
        "issues",
        "logs",
    ]

    for key in candidate_keys:
        value = summary_json.get(key)

        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            nested = _extract_findings_container(value)

            if nested:
                return nested

    for value in summary_json.values():
        if isinstance(value, list) and value:
            return value

        if isinstance(value, dict):
            nested = _extract_findings_container(value)

            if nested:
                return nested

    return []


def read_summary(path: Path) -> Tuple[int, Any]:
    """
    Lee dalfox.json y devuelve:

    - cantidad de hallazgos crudos no vacíos;
    - documento JSON completo.
    """
    path = Path(path)
    summary_json = _read_json_file(path)
    findings = _extract_findings_container(summary_json)

    non_empty_findings = [
        item
        for item in findings
        if isinstance(item, dict) and item
    ]

    return len(non_empty_findings), summary_json


# ==========================================================
# NORMALIZACIÓN DE HALLAZGOS
# ==========================================================

def _first_non_empty(item: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    """
    Devuelve el primer valor no vacío de un diccionario.
    """
    for key in keys:
        value = item.get(key)

        if value is None:
            continue

        if isinstance(value, str):
            if value.strip():
                return value.strip()
            continue

        return value

    return None


def _stringify_value(value: Any) -> str:
    """
    Convierte un valor a texto seguro.
    """
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _decode_url_value(value: Any) -> str:
    """
    Decodifica un valor de URL para mostrar payloads legibles.
    """
    text = _stringify_value(value)

    if not text:
        return ""

    try:
        return unquote_plus(text)
    except Exception:
        return text


def _parse_query_single_values(url: str) -> Dict[str, str]:
    """
    Devuelve parámetros query como diccionario simple.
    """
    result: Dict[str, str] = {}

    try:
        parsed = urlsplit(url or "")
        query = parse_qs(parsed.query, keep_blank_values=True)

        for key, values in query.items():
            if not key:
                continue

            first_value = ""

            if isinstance(values, list) and values:
                first_value = values[0]
            elif isinstance(values, str):
                first_value = values

            result[str(key)] = _decode_url_value(first_value)

    except Exception:
        return {}

    return result


def _infer_parameter_from_url(target_url: str) -> str:
    """
    Intenta inferir el parámetro cuando la URL tiene un único query param.
    """
    query = _parse_query_single_values(target_url)

    if len(query) == 1:
        return next(iter(query.keys()))

    return ""


def _infer_parameter_and_payload_from_poc_url(
    poc_url: str,
    fallback_target_url: str,
) -> Tuple[str, str]:
    """
    Extrae parámetro y payload desde la URL explotada que Dalfox guarda en data.
    """
    poc_query = _parse_query_single_values(poc_url)
    fallback_query = _parse_query_single_values(fallback_target_url)

    if not poc_query:
        return "", ""

    for key, poc_value in poc_query.items():
        fallback_value = fallback_query.get(key)

        if fallback_value is None:
            return key, poc_value

        if str(poc_value) != str(fallback_value):
            return key, poc_value

    first_key = next(iter(poc_query.keys()))
    return first_key, poc_query.get(first_key, "")


def _normalize_severity(value: Any, raw_item: Dict[str, Any]) -> str:
    """
    Normaliza la severidad del hallazgo.
    """
    text = _stringify_value(value).lower()

    if text in {"critical", "crítica", "critica"}:
        return "Critical"

    if text in {"high", "alta"}:
        return "High"

    if text in {"medium", "media"}:
        return "Medium"

    if text in {"low", "baja"}:
        return "Low"

    if text in {"info", "informational", "informativa"}:
        return "Informational"

    raw_blob = json.dumps(raw_item, ensure_ascii=False).lower()

    if "verified" in raw_blob or "vulnerable" in raw_blob or "vuln" in raw_blob:
        return "High"

    if "xss" in raw_blob:
        return "Medium"

    return "Medium"


def _normalize_inject_type(value: Any) -> str:
    """
    Normaliza el tipo técnico de inyección reportado por Dalfox.
    """
    text = _stringify_value(value).strip()

    if not text:
        return ""

    lowered = text.lower()

    if lowered == "headless":
        return "headless / DOM XSS"

    if "dom" in lowered:
        return "DOM XSS"

    return text


def _build_evidence_text(
    raw_finding: Dict[str, Any],
    inject_type_display: str,
) -> str:
    """
    Construye una evidencia legible para la GUI.

    Evita mostrar únicamente:
      Triggered XSS Payload (found dialog in headless)

    En su lugar muestra una confirmación entendible.
    """
    message = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "message_str",
                "message",
                "evidence",
                "evidence_text",
                "description",
                "detail",
                "proof",
            ],
        )
    )

    lowered_message = message.lower()
    lowered_type = (inject_type_display or "").lower()

    if "found dialog in headless" in lowered_message or "headless" in lowered_type:
        return (
            "Confirmación headless: Dalfox ejecutó el payload en Chromium "
            "y detectó un diálogo JavaScript."
        )

    if "found dom object" in lowered_message or "dom" in lowered_type:
        return (
            "Confirmación DOM: Dalfox detectó que el payload fue reflejado "
            "en un objeto del DOM."
        )

    if "triggered xss payload" in lowered_message:
        return (
            "Confirmación XSS: Dalfox reportó que el payload fue activado "
            "durante la verificación."
        )

    return message or "Confirmación XSS registrada por Dalfox."


def _normalize_single_finding(
    raw_finding: Any,
    fallback_target_url: str,
    index: int,
) -> Optional[Dict[str, Any]]:
    """
    Normaliza un hallazgo crudo de Dalfox.

    Corrección visual:
    - Para headless/DOM XSS, Dalfox puede traer param/payload/evidence vacíos.
    - En ese caso:
        parámetro = se infiere desde la URL explotada en data.
        payload = solo el valor inyectado del parámetro.
        evidencia = texto claro de confirmación.
    - La URL completa explotada se conserva como poc_url/request_url.
    """
    if raw_finding is None:
        return None

    if isinstance(raw_finding, str):
        evidence = raw_finding.strip()

        if not evidence:
            return None

        parameter = _infer_parameter_from_url(fallback_target_url)

        return {
            "source": DALFOX_SOURCE_NAME,
            "index": index,
            "target_url": fallback_target_url,
            "url": fallback_target_url,
            "request_url": fallback_target_url,
            "poc_url": "",
            "parameter": parameter or "-",
            "param": parameter or "-",
            "payload": evidence,
            "evidence": evidence,
            "evidence_text": evidence,
            "severity": "Medium",
            "risk": "Medium",
            "type": "xss",
            "poc_type": None,
            "method": "GET",
            "inject_type": "",
            "xss_type_display": "XSS",
            "raw": raw_finding,
        }

    if not isinstance(raw_finding, dict) or not raw_finding:
        return None

    poc_url = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "data",
                "request_url",
                "poc_url",
            ],
        )
    )

    target_url = fallback_target_url

    inferred_parameter, inferred_payload = _infer_parameter_and_payload_from_poc_url(
        poc_url=poc_url,
        fallback_target_url=fallback_target_url,
    )

    parameter = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "param",
                "parameter",
                "query",
                "name",
                "variable",
                "injection_point",
                "inject_param",
            ],
        )
    )

    if not parameter:
        parameter = inferred_parameter or _infer_parameter_from_url(fallback_target_url)

    payload = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "payload",
                "poc",
                "poc_code",
                "vector",
                "injected",
                "attack",
                "value",
            ],
        )
    )

    if not payload:
        payload = inferred_payload

    inject_type_raw = _first_non_empty(
        raw_finding,
        [
            "inject_type",
            "injection_type",
            "sink",
            "context",
        ],
    )

    inject_type_display = _normalize_inject_type(inject_type_raw)

    evidence = _build_evidence_text(
        raw_finding=raw_finding,
        inject_type_display=inject_type_display,
    )

    finding_type = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "type",
                "issue_type",
                "vuln_type",
                "category",
            ],
        )
    ) or "xss"

    poc_type = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "poc_type",
                "proof_type",
            ],
        )
    )

    method = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "method",
                "http_method",
            ],
        )
    ) or "GET"

    severity = _normalize_severity(
        _first_non_empty(raw_finding, ["severity", "risk", "level"]),
        raw_finding,
    )

    if not payload and not evidence and not poc_url:
        return None

    normalized = {
        "source": DALFOX_SOURCE_NAME,
        "index": index,

        "target_url": target_url,
        "url": target_url,
        "request_url": target_url,

        "poc_url": poc_url,

        "parameter": parameter or "-",
        "param": parameter or "-",
        "payload": payload or "-",
        "evidence": evidence or "-",
        "evidence_text": evidence or "-",

        "severity": severity,
        "risk": severity,
        "type": finding_type,
        "poc_type": poc_type,
        "method": method,
        "inject_type": _stringify_value(inject_type_raw),
        "xss_type_display": inject_type_display or "XSS",

        "raw": raw_finding,
    }

    optional_mappings = {
        "line": ["line", "line_number"],
        "cwe": ["cwe", "cwe_id"],
        "context": ["context", "sink", "dom_sink"],
        "verification": ["verification", "verified", "headless_verified"],
        "message_str": ["message_str"],
    }

    for target_key, source_keys in optional_mappings.items():
        optional_value = _first_non_empty(raw_finding, source_keys)

        if optional_value is not None:
            normalized[target_key] = optional_value

    return normalized


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Elimina duplicados simples.
    """
    seen: set[tuple[str, str, str, str]] = set()
    unique: List[Dict[str, Any]] = []

    for finding in findings:
        key = (
            _stringify_value(finding.get("target_url")),
            _stringify_value(finding.get("parameter")),
            _stringify_value(finding.get("payload"))[:300],
            _stringify_value(finding.get("evidence"))[:300],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(finding)

    return unique


def extract_structured_findings(
    summary_json: Any,
    fallback_target_url: str,
) -> List[Dict[str, Any]]:
    """
    Extrae y normaliza hallazgos XSS desde la salida JSON de Dalfox.

    Retorna:
    - lista de hallazgos estructurados para xss_repository.py.
    """
    raw_findings = _extract_findings_container(summary_json)
    structured: List[Dict[str, Any]] = []

    for index, raw_finding in enumerate(raw_findings or [], start=1):
        normalized = _normalize_single_finding(
            raw_finding=raw_finding,
            fallback_target_url=fallback_target_url,
            index=index,
        )

        if normalized:
            structured.append(normalized)

    return _deduplicate_findings(structured)