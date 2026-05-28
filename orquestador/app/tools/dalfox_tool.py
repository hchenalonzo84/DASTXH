"""
dalfox_tool.py
- Wrapper de ejecución de Dalfox para DASTXH.

Objetivo:
- Ejecutar la capa XSS del prototipo de forma controlada.
- Generar evidencia JSON y TXT compatible con scanner_service.py.
- Normalizar hallazgos para persistencia en PostgreSQL.
- Activar evaluación DOM XSS profunda cuando esté configurado.

Soporte DOM XSS:
- DASTXH puede activar:
    --deep-domxss
    --force-headless-verification

Esto permite que Dalfox intente validar casos donde el XSS depende de ejecución
JavaScript en navegador/headless, por ejemplo páginas que leen parámetros de la URL
y los insertan en el DOM.

Importante:
- Chromium debe estar instalado en el contenedor del orquestador.
- El Dockerfile debe exponer CHROME_BIN / CHROMIUM_BIN.
- El timeout duro de Dalfox se controla desde configuración para evitar ejecuciones
  indefinidas.
"""

from __future__ import annotations

import json
import os
import subprocess
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

import config


# ==========================================================
# CONSTANTES INTERNAS
# ==========================================================

DALFOX_TIMEOUT_EXIT_CODE = 124
DALFOX_SOURCE_NAME = "dalfox"


# ==========================================================
# HELPERS DE CONFIGURACIÓN
# ==========================================================

def _env_to_bool(value: Any, default: bool = False) -> bool:
    """
    Convierte valores típicos de entorno a booleano.

    Acepta:
    - true / false
    - 1 / 0
    - yes / no
    - y / n
    - on / off
    """
    if value is None:
        return default

    normalized = str(value).strip().lower()

    if normalized in {"1", "true", "yes", "y", "on", "si", "sí"}:
        return True

    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    return default


def _get_config_bool(
    env_name: str,
    config_attr: str,
    default: bool,
) -> bool:
    """
    Lee un booleano primero desde variable de entorno y luego desde config.py.
    """
    if env_name in os.environ:
        return _env_to_bool(os.getenv(env_name), default=default)

    return bool(getattr(config, config_attr, default))


def _get_config_int(
    env_name: str,
    config_attr: str,
    default: int,
) -> int:
    """
    Lee un entero primero desde variable de entorno y luego desde config.py.
    """
    raw_value = os.getenv(env_name)

    if raw_value is None:
        raw_value = getattr(config, config_attr, default)

    try:
        parsed = int(raw_value)
    except Exception:
        parsed = default

    if parsed <= 0:
        return default

    return parsed


def _get_dalfox_request_timeout(timeout_s: Optional[int]) -> int:
    """
    Calcula el timeout por solicitud que se enviará a Dalfox.

    Regla:
    - Se toma el valor de configuración DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS.
    - Si el flujo recibió un timeout base menor, se respeta el menor.
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
    Obtiene el timeout duro para el proceso completo de Dalfox.

    Este valor protege a DASTXH para que Dalfox no deje una ejecución
    indefinidamente en estado running.
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
    Indica si se permite minería ligera de Dalfox.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_LIGHT_MINING_ENABLED",
        config_attr="DALFOX_LIGHT_MINING_ENABLED",
        default=True,
    )


def _should_skip_mining_dom() -> bool:
    """
    Indica si se debe omitir la minería DOM de Dalfox.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_SKIP_MINING_DOM",
        config_attr="DALFOX_SKIP_MINING_DOM",
        default=False,
    )


def _should_skip_mining_dict() -> bool:
    """
    Indica si se debe omitir la minería por diccionario de Dalfox.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_SKIP_MINING_DICT",
        config_attr="DALFOX_SKIP_MINING_DICT",
        default=False,
    )


def _is_deep_domxss_enabled() -> bool:
    """
    Indica si DASTXH debe activar --deep-domxss.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_DEEP_DOMXSS_ENABLED",
        config_attr="DALFOX_DEEP_DOMXSS_ENABLED",
        default=True,
    )


def _is_force_headless_verification_enabled() -> bool:
    """
    Indica si DASTXH debe activar --force-headless-verification.
    """
    return _get_config_bool(
        env_name="DASTXH_DALFOX_FORCE_HEADLESS_VERIFICATION",
        config_attr="DALFOX_FORCE_HEADLESS_VERIFICATION",
        default=True,
    )


# ==========================================================
# HELPERS DE ARCHIVOS JSON
# ==========================================================

def _write_json_file(path: Path, payload: Any) -> None:
    """
    Escribe un archivo JSON de forma segura.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
        errors="replace",
    )


def _read_json_file(path: Path) -> Any:
    """
    Lee un archivo JSON.

    Si falla, devuelve un documento estructurado de error.
    """
    try:
        if not path.exists() or not path.is_file():
            return {
                "ok": False,
                "error": "El archivo JSON de Dalfox no existe.",
                "findings": [],
            }

        raw_text = path.read_text(encoding="utf-8", errors="replace").strip()

        if not raw_text:
            return {
                "ok": False,
                "error": "El archivo JSON de Dalfox está vacío.",
                "findings": [],
            }

        return json.loads(raw_text)

    except Exception as exc:
        return {
            "ok": False,
            "error": f"No fue posible leer el JSON de Dalfox: {str(exc)}",
            "findings": [],
        }


def _is_valid_json_file(path: Path) -> bool:
    """
    Verifica si un archivo existe y contiene JSON válido.
    """
    try:
        if not path.exists() or not path.is_file():
            return False

        raw_text = path.read_text(encoding="utf-8", errors="replace").strip()

        if not raw_text:
            return False

        json.loads(raw_text)
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
    Escribe un JSON mínimo cuando Dalfox no generó un archivo JSON válido.

    Esto evita que read_summary falle y permite que DASTXH registre
    evidencia técnica aunque la herramienta termine sin hallazgos o con error.
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
# CONSTRUCCIÓN DEL COMANDO DALFOX
# ==========================================================

def _build_dalfox_command(
    url: str,
    out_json: Path,
    timeout_s: Optional[int],
    scan_profile: Optional[str],
) -> List[str]:
    """
    Construye el comando real de Dalfox.

    Este es el punto donde se activan los flags DOM XSS:

    - --deep-domxss
    - --force-headless-verification

    También se controla:
    - formato JSON;
    - archivo de salida;
    - timeout por solicitud;
    - workers;
    - minería DOM/diccionario.
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

    # ------------------------------------------------------
    # Minería de Dalfox
    # ------------------------------------------------------
    # Si la minería ligera está deshabilitada, se omiten las
    # dos fuentes principales de minería para reducir alcance.
    if not _is_light_mining_enabled():
        cmd.append("--skip-mining-dom")
        cmd.append("--skip-mining-dict")
    else:
        if _should_skip_mining_dom():
            cmd.append("--skip-mining-dom")

        if _should_skip_mining_dict():
            cmd.append("--skip-mining-dict")

    # ------------------------------------------------------
    # DOM XSS profundo / headless
    # ------------------------------------------------------
    if _is_deep_domxss_enabled():
        cmd.append("--deep-domxss")

    if _is_force_headless_verification_enabled():
        cmd.append("--force-headless-verification")

    return cmd


def _build_dalfox_runtime_env() -> Dict[str, str]:
    """
    Construye el entorno para ejecutar Dalfox.

    Se asegura de que Chromium pueda ser localizado por herramientas
    que dependen de navegador headless.
    """
    env = dict(os.environ)

    env.setdefault("CHROME_BIN", "/usr/bin/chromium")
    env.setdefault("CHROMIUM_BIN", "/usr/bin/chromium")

    return env


def run_dalfox(
    url: str,
    timeout_s: int,
    out_json: Path,
    scan_profile: str = "profundo",
) -> Tuple[int, str]:
    """
    Ejecuta Dalfox contra una URL objetivo.

    Parámetros:
    - url: URL objetivo.
    - timeout_s: timeout base recibido desde el flujo DASTXH.
    - out_json: ruta donde Dalfox debe escribir su salida JSON.
    - scan_profile: valor técnico conservado por compatibilidad.

    Retorna:
    - tool_rc: código de salida de Dalfox.
    - raw_output: stdout + stderr para guardar como dalfox.txt.

    Importante:
    - El timeout duro del proceso se controla con subprocess.run(timeout=...).
    - Si Dalfox no genera JSON válido, se crea un JSON fallback.
    """
    out_json = Path(out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # Evita reutilizar evidencia vieja si una ejecución previa dejó archivo.
    try:
        if out_json.exists():
            out_json.unlink()
    except Exception:
        pass

    hard_timeout = _get_dalfox_hard_timeout()
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
            "[DASTXH] Dalfox command\n"
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
            "[DASTXH] Dalfox timeout\n"
            f"Dalfox superó el límite duro de {hard_timeout} segundos.\n\n"
            "[DASTXH] Dalfox command\n"
            f"{command_for_log}\n\n"
            "[DASTXH] Dalfox stdout parcial\n"
            f"{stdout}\n\n"
            "[DASTXH] Dalfox stderr parcial\n"
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
            "[DASTXH] Dalfox execution error\n"
            f"{str(exc)}\n\n"
            "[DASTXH] Traceback\n"
            f"{traceback.format_exc()}\n\n"
            "[DASTXH] Dalfox command\n"
            f"{command_for_log}\n"
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
    Extrae la lista más probable de hallazgos desde diferentes formatos
    posibles de salida JSON de Dalfox.

    Dalfox puede variar el formato entre versiones. Por eso se contemplan:
    - lista directa;
    - claves findings/results/data/pocs/vulnerabilities/logs;
    - estructuras anidadas.
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

    # Búsqueda defensiva en valores anidados.
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
    Lee el JSON de Dalfox y devuelve:

    - cantidad de hallazgos crudos;
    - documento JSON completo.

    Esta función se mantiene compatible con scanner_service.py.
    """
    path = Path(path)
    summary_json = _read_json_file(path)
    findings = _extract_findings_container(summary_json)

    return len(findings), summary_json
# ==========================================================
# NORMALIZACIÓN DE HALLAZGOS
# ==========================================================

def _first_non_empty(item: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    """
    Devuelve el primer valor no vacío encontrado en un diccionario.
    """
    for key in keys:
        value = item.get(key)

        if value is None:
            continue

        if isinstance(value, str) and value.strip():
            return value.strip()

        if not isinstance(value, str):
            return value

    return None


def _stringify_value(value: Any) -> str:
    """
    Convierte un valor a texto seguro para guardar como evidencia.
    """
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _infer_parameter_from_url(target_url: str) -> str:
    """
    Intenta inferir el parámetro cuando la URL tiene un único parámetro query.
    """
    try:
        parsed = urlsplit(target_url or "")
        query = parse_qs(parsed.query, keep_blank_values=True)

        if len(query) == 1:
            return next(iter(query.keys()))

    except Exception:
        pass

    return ""


def _normalize_severity(value: Any, raw_item: Dict[str, Any]) -> str:
    """
    Normaliza severidad de Dalfox a valores simples usados por DASTXH.
    """
    raw = _stringify_value(value).lower()

    if raw in {"critical", "crítica", "critica"}:
        return "Critical"

    if raw in {"high", "alta"}:
        return "High"

    if raw in {"medium", "media"}:
        return "Medium"

    if raw in {"low", "baja"}:
        return "Low"

    if raw in {"info", "informational", "informativa"}:
        return "Informational"

    # Si Dalfox marca como verified/vuln, se considera alta.
    raw_blob = json.dumps(raw_item, ensure_ascii=False).lower()

    if "verified" in raw_blob or "vulnerable" in raw_blob or "vuln" in raw_blob:
        return "High"

    if "xss" in raw_blob:
        return "Medium"

    return "Medium"


def _normalize_single_finding(
    raw_finding: Any,
    fallback_target_url: str,
    index: int,
) -> Optional[Dict[str, Any]]:
    """
    Convierte un hallazgo crudo de Dalfox a una estructura estable.

    Se incluyen alias de campos para mantener compatibilidad con repositorios,
    vistas e interpretación IA.
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
            "parameter": parameter,
            "param": parameter,
            "payload": evidence,
            "evidence": evidence,
            "evidence_text": evidence,
            "severity": "Medium",
            "risk": "Medium",
            "type": "xss",
            "poc_type": None,
            "method": "GET",
            "raw": raw_finding,
        }

    if not isinstance(raw_finding, dict):
        return None

    target_url = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "url",
                "target",
                "target_url",
                "request_url",
                "data",
            ],
        )
    ) or fallback_target_url

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
        parameter = _infer_parameter_from_url(target_url or fallback_target_url)

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

    evidence = _stringify_value(
        _first_non_empty(
            raw_finding,
            [
                "evidence",
                "evidence_text",
                "message",
                "data",
                "description",
                "detail",
                "output",
                "proof",
            ],
        )
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
                "inject_type",
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

    # Si no hay payload ni evidencia, el registro no aporta como hallazgo.
    # Se descarta para no llenar la GUI con filas vacías.
    if not payload and not evidence:
        return None

    normalized = {
        "source": DALFOX_SOURCE_NAME,
        "index": index,
        "target_url": target_url or fallback_target_url,
        "url": target_url or fallback_target_url,
        "parameter": parameter,
        "param": parameter,
        "payload": payload or evidence,
        "evidence": evidence or payload,
        "evidence_text": evidence or payload,
        "severity": severity,
        "risk": severity,
        "type": finding_type,
        "poc_type": poc_type,
        "method": method,
        "raw": raw_finding,
    }

    # Campos opcionales útiles si vienen en el JSON de Dalfox.
    optional_mappings = {
        "line": ["line", "line_number"],
        "cwe": ["cwe", "cwe_id"],
        "context": ["context", "sink", "dom_sink"],
        "verification": ["verification", "verified", "headless_verified"],
    }

    for target_key, source_keys in optional_mappings.items():
        optional_value = _first_non_empty(raw_finding, source_keys)

        if optional_value is not None:
            normalized[target_key] = optional_value

    return normalized


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Elimina duplicados simples para no inflar resultados.
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

    Esta función se mantiene compatible con scanner_service.py.

    Retorna:
    - lista de hallazgos estructurados.
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