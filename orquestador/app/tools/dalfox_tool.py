"""
dalfox_tool.py
- CAPA XSS: Dalfox.
- Ejecuta Dalfox en modo URL y normaliza hallazgos.

Objetivos de esta versión:
- usar una sola configuración estándar de Dalfox;
- mantener compatibilidad con llamadas antiguas que todavía envíen scan_profile;
- aplicar timeout duro para evitar ejecuciones indefinidas;
- limitar workers para mejorar estabilidad;
- permitir minería ligera controlada desde .env;
- evitar minería agresiva por defecto;
- ignorar salidas vacías como [{}] para no contarlas como XSS;
- entregar datos más limpios a BD, GUI e IA.

Decisión actual:
- DASTXH ejecuta un flujo único: evaluación profunda controlada.
- El usuario ya no elige perfil desde la GUI.
- Dalfox puede usar minería ligera para mejorar cobertura sin convertir
  la prueba en una exploración excesivamente variable.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import (
    DALFOX_HARD_TIMEOUT_SECONDS,
    DALFOX_LIGHT_MINING_ENABLED,
    DALFOX_REQUEST_TIMEOUT_SECONDS,
    DALFOX_SKIP_MINING_DICT,
    DALFOX_SKIP_MINING_DOM,
    DALFOX_WORKERS,
    UA,
)


# ==========================================================
# HELPERS DE CONFIGURACIÓN
# ==========================================================

def _env_bool(name: str, default: bool) -> bool:
    """
    Lee un booleano desde variable de entorno.

    Valores aceptados como verdadero:
    true, 1, yes, y, on, si, sí

    Valores aceptados como falso:
    false, 0, no, n, off
    """
    value = os.getenv(name)

    if value is None:
        return default

    normalized = value.strip().lower()

    if normalized in ("true", "1", "yes", "y", "on", "si", "sí"):
        return True

    if normalized in ("false", "0", "no", "n", "off"):
        return False

    return default


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    """
    Lee un entero desde variable de entorno y lo limita a un rango seguro.
    """
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed = int(value.strip())
    except Exception:
        return default

    return max(min_value, min(max_value, parsed))


def _request_timeout(timeout_s: int) -> int:
    """
    Define el timeout por request que recibirá Dalfox.

    Este no es el timeout global del proceso.
    Es el límite que Dalfox usa para solicitudes individuales.

    Se toma como base:
    - timeout_s recibido desde la GUI/backend;
    - DALFOX_REQUEST_TIMEOUT_SECONDS definido en config.py;
    - DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS definido en .env.

    Nota:
    El valor de .env tiene prioridad para poder afinar el comportamiento
    sin modificar código.
    """
    default_value = int(timeout_s or DALFOX_REQUEST_TIMEOUT_SECONDS)

    # Si el usuario ingresa un valor menor desde la GUI, no lo usamos para
    # recortar agresivamente Dalfox. En esta fase buscamos estabilidad.
    default_value = max(default_value, DALFOX_REQUEST_TIMEOUT_SECONDS)

    return _env_int(
        "DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS",
        default=default_value,
        min_value=5,
        max_value=180,
    )


def _hard_timeout() -> int:
    """
    Define el timeout duro del proceso Dalfox completo.

    Esto evita que una URL pública o un laboratorio lento deje la ejecución
    indefinidamente en estado running.
    """
    return _env_int(
        "DASTXH_DALFOX_HARD_TIMEOUT_SECONDS",
        default=DALFOX_HARD_TIMEOUT_SECONDS,
        min_value=60,
        max_value=1800,
    )


def _workers() -> int:
    """
    Define la cantidad de workers de Dalfox.

    Se evita depender del valor por defecto de Dalfox porque puede generar
    demasiada concurrencia y resultados menos estables en ciertos entornos.
    """
    return _env_int(
        "DASTXH_DALFOX_WORKERS",
        default=DALFOX_WORKERS,
        min_value=1,
        max_value=100,
    )


def _light_mining_enabled() -> bool:
    """
    Define si Dalfox usará minería ligera.

    Variable nueva:
    - DASTXH_DALFOX_LIGHT_MINING_ENABLED

    Compatibilidad:
    - Si todavía existe DASTXH_DALFOX_SKIP_MINING_ALL en .env,
      se interpreta de forma inversa:
        true  -> minería ligera desactivada
        false -> minería ligera activada
    """
    legacy_skip_all = os.getenv("DASTXH_DALFOX_SKIP_MINING_ALL")

    if legacy_skip_all is not None:
        skip_all = _env_bool("DASTXH_DALFOX_SKIP_MINING_ALL", default=False)
        return not skip_all

    return _env_bool(
        "DASTXH_DALFOX_LIGHT_MINING_ENABLED",
        default=DALFOX_LIGHT_MINING_ENABLED,
    )


def _skip_mining_dom() -> bool:
    """
    Define si se omite la minería DOM.

    Para una minería ligera, normalmente conviene omitir DOM porque puede
    aumentar tiempo y variabilidad.
    """
    return _env_bool(
        "DASTXH_DALFOX_SKIP_MINING_DOM",
        default=DALFOX_SKIP_MINING_DOM,
    )


def _skip_mining_dict() -> bool:
    """
    Define si se omite la minería por diccionario.

    Para una minería ligera, normalmente conviene omitir diccionario porque
    puede ampliar demasiado el alcance del escaneo.
    """
    return _env_bool(
        "DASTXH_DALFOX_SKIP_MINING_DICT",
        default=DALFOX_SKIP_MINING_DICT,
    )


def _ensure_json_array_file(path: Path) -> None:
    """
    Garantiza que el archivo JSON exista con una lista vacía.

    Se usa cuando Dalfox falla o llega a timeout antes de cerrar el JSON.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists() or not path.read_text(encoding="utf-8", errors="replace").strip():
            path.write_text("[]", encoding="utf-8")
            return

        raw = path.read_text(encoding="utf-8", errors="replace").strip()

        try:
            json.loads(raw)
        except Exception:
            path.write_text("[]", encoding="utf-8")
    except Exception:
        # Este helper no debe romper el escaneo.
        pass
# ==========================================================
# CONSTRUCCIÓN DEL COMANDO DALFOX
# ==========================================================

def _build_dalfox_command(
    url: str,
    out_json: Path,
    request_timeout: int,
    workers: int,
    light_mining_enabled: bool,
    skip_mining_dom: bool,
    skip_mining_dict: bool,
) -> List[str]:
    """
    Construye el comando Dalfox con configuración estándar.

    Reglas actuales:
    - siempre se usa modo URL;
    - se sigue redirección con -F;
    - se define User-Agent estable;
    - se controla número de workers;
    - se permite minería ligera si está habilitada;
    - si minería ligera está deshabilitada, se usa --skip-mining-all.
    """
    cmd = [
        "dalfox", "url", url,
        "--no-color",
        "--no-spinner",
        "--format", "json",
        "-o", str(out_json),
        "--timeout", str(request_timeout),
        "--worker", str(workers),
        "--user-agent", UA,
        "-F",
    ]

    if not light_mining_enabled:
        cmd.append("--skip-mining-all")
        return cmd

    # Minería ligera controlada:
    # Permitimos que Dalfox conserve una minería básica, pero omitimos
    # partes que tienden a aumentar demasiado el alcance.
    if skip_mining_dom:
        cmd.append("--skip-mining-dom")

    if skip_mining_dict:
        cmd.append("--skip-mining-dict")

    return cmd


def _command_to_text(cmd: List[str]) -> str:
    """
    Convierte el comando a texto para dejarlo documentado en dalfox.txt.

    No se usa para ejecutar; solo para trazabilidad.
    """
    return " ".join(str(part) for part in cmd)


# ==========================================================
# EJECUCIÓN DALFOX
# ==========================================================

def run_dalfox(
    url: str,
    timeout_s: int,
    out_json: Path,
    scan_profile: str = "profundo",
) -> Tuple[int, str]:
    """
    Ejecuta Dalfox contra una URL y devuelve:
    - código de retorno;
    - salida combinada stdout + stderr.

    Parámetro scan_profile:
    - Se conserva por compatibilidad con scanner_service.py.
    - Ya no cambia la configuración interna.
    - DASTXH usa ahora un flujo único de evaluación profunda controlada.
    """
    request_timeout = _request_timeout(timeout_s)
    hard_timeout = _hard_timeout()
    workers = _workers()
    light_mining_enabled = _light_mining_enabled()
    skip_mining_dom = _skip_mining_dom()
    skip_mining_dict = _skip_mining_dict()

    out_json.parent.mkdir(parents=True, exist_ok=True)

    cmd = _build_dalfox_command(
        url=url,
        out_json=out_json,
        request_timeout=request_timeout,
        workers=workers,
        light_mining_enabled=light_mining_enabled,
        skip_mining_dom=skip_mining_dom,
        skip_mining_dict=skip_mining_dict,
    )

    config_note = (
        "[DASTXH] Configuración Dalfox aplicada: "
        f"request_timeout={request_timeout}s, "
        f"hard_timeout={hard_timeout}s, "
        f"workers={workers}, "
        f"light_mining_enabled={light_mining_enabled}, "
        f"skip_mining_dom={skip_mining_dom}, "
        f"skip_mining_dict={skip_mining_dict}, "
        "flow=evaluacion_profunda_controlada\n"
        f"[DASTXH] Comando Dalfox: {_command_to_text(cmd)}"
    )

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=hard_timeout,
            check=False,
        )

        raw = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        raw = f"{config_note}\n{raw}"

        # Si Dalfox termina sin escribir JSON válido, dejamos [] para que el
        # pipeline pueda cerrar de forma limpia.
        _ensure_json_array_file(out_json)

        return int(completed.returncode), raw

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        _ensure_json_array_file(out_json)

        raw = (
            f"{config_note}\n"
            f"{stdout}\n{stderr}\n"
            f"[DASTXH] Dalfox superó el timeout duro de {hard_timeout} segundos. "
            "La fase XSS se cerró sin hallazgos válidos para evitar que la ejecución "
            "quede indefinidamente en running."
        )

        # 124 es un código convencional para timeout.
        return 124, raw

    except FileNotFoundError:
        _ensure_json_array_file(out_json)

        return (
            127,
            f"{config_note}\n"
            "[DASTXH] No se encontró el binario 'dalfox' dentro del contenedor. "
            "Verifica el Dockerfile y la instalación de la herramienta.",
        )

    except Exception as exc:
        _ensure_json_array_file(out_json)

        return (
            1,
            f"{config_note}\n"
            f"[DASTXH] Error inesperado al ejecutar Dalfox: {type(exc).__name__}: {exc}",
        )


# ==========================================================
# LECTURA / NORMALIZACIÓN DE SALIDA
# ==========================================================

def _value_to_text(value: Any) -> Optional[str]:
    """
    Convierte un valor de Dalfox a texto útil.

    Si el valor es dict/list, se serializa como JSON compacto para no perder
    evidencia estructurada.
    """
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            text = str(value)
    else:
        text = str(value)

    text = text.strip()
    return text if text else None


def _pick_first_text(source: Dict[str, Any], keys: List[str]) -> Optional[str]:
    """
    Busca la primera clave disponible con contenido textual útil.
    """
    for key in keys:
        value = source.get(key)
        text = _value_to_text(value)

        if text:
            return text

    return None


def _normalize_optional_text(value: Any) -> Optional[str]:
    """
    Convierte un valor a texto útil o None si queda vacío.
    """
    return _value_to_text(value)


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
def _has_meaningful_content(
    param_name: Optional[str],
    payload: Optional[str],
    evidence: Optional[str],
    severity: Optional[str],
    source_type: Optional[str],
) -> bool:
    """
    Decide si un registro de Dalfox representa un hallazgo útil.

    Importante:
    - No se usa target_url para validar contenido, porque cuando fallback_target_url
      se agregaba a un objeto vacío {}, DASTXH lo contaba como hallazgo.
    - Para considerar un hallazgo como útil debe existir al menos payload/evidencia,
      o una combinación mínima de parámetro + severidad/fuente.
    """
    has_payload = bool(payload and payload.strip())
    has_evidence = bool(evidence and evidence.strip())
    has_param = bool(param_name and param_name.strip())
    has_severity = bool(severity and severity.strip())
    has_source_type = bool(source_type and source_type.strip())

    if has_payload or has_evidence:
        return True

    if has_param and (has_severity or has_source_type):
        return True

    return False


def _raw_item_has_meaningful_signal(item: Any) -> bool:
    """
    Evalúa una entrada cruda de Dalfox antes de contarla.

    Evita que [{}] se cuente como 1 hallazgo.
    """
    if isinstance(item, dict):
        if not item:
            return False

        source_type = _pick_first_text(item, ["type", "source", "kind", "category"])
        param_name = _pick_first_text(item, ["param", "parameter", "param_name", "key"])
        payload = _pick_first_text(item, ["payload", "poc", "proof", "vector", "inject"])
        evidence = _pick_first_text(item, ["evidence", "message", "detail", "trigger", "reflected"])
        severity = _pick_first_text(item, ["severity", "risk", "priority", "level"])

        return _has_meaningful_content(
            param_name=param_name,
            payload=payload,
            evidence=evidence,
            severity=severity,
            source_type=source_type,
        )

    text = _normalize_optional_text(item)
    return bool(text)


def _finding_signature(finding: Dict[str, Any]) -> str:
    """
    Construye una firma estable para deduplicar hallazgos.

    Esto evita que payloads idénticos se muestren varias veces si Dalfox
    devuelve registros repetidos.
    """
    param_name = _normalize_optional_text(finding.get("param_name")) or ""
    payload = _normalize_optional_text(finding.get("payload")) or ""
    evidence = _normalize_optional_text(finding.get("evidence")) or ""
    severity = _normalize_optional_text(finding.get("severity")) or ""
    source_type = _normalize_optional_text(finding.get("source_type")) or ""

    return "|".join(
        [
            param_name.lower(),
            payload,
            evidence,
            severity.lower(),
            source_type.lower(),
        ]
    )


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Elimina hallazgos duplicados conservando el primer registro observado.

    Luego reasigna finding_order para que la tabla no tenga saltos.
    """
    seen: set[str] = set()
    deduplicated: List[Dict[str, Any]] = []

    for finding in findings:
        signature = _finding_signature(finding)

        if signature in seen:
            continue

        seen.add(signature)
        deduplicated.append(dict(finding))

    for index, finding in enumerate(deduplicated, start=1):
        finding["finding_order"] = index

    return deduplicated


def read_summary(out_json: Path) -> tuple[int, Any]:
    """
    Lee el archivo JSON de Dalfox y devuelve:
    - findings_count útil;
    - summary_json original.

    Se mantiene flexible porque Dalfox puede cambiar la forma exacta del JSON
    entre versiones. Además, filtra objetos vacíos como [{}].
    """
    if not out_json.exists():
        return 0, {"_no_json": True}

    try:
        raw_text = out_json.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return 0, {"_read_error": True}

    if not raw_text:
        return 0, []

    try:
        data = json.loads(raw_text)
    except Exception:
        return 0, {
            "_parse_error": True,
            "_raw_preview": raw_text[:500],
        }

    raw_findings = _coerce_findings_list(data)
    findings = sum(1 for item in raw_findings if _raw_item_has_meaningful_signal(item))

    return findings, data


def extract_structured_findings(
    summary_json: Any,
    fallback_target_url: str | None = None,
) -> List[Dict[str, Any]]:
    """
    Convierte la salida estructurada de Dalfox en una lista de hallazgos
    normalizados para persistencia en la tabla xss_findings.

    Campos que intentamos extraer:
    - finding_order;
    - source_type;
    - target_url;
    - param_name;
    - payload;
    - evidence;
    - severity;
    - raw_finding_json.

    Si Dalfox devuelve [{}], [], o registros sin payload/evidencia/parámetro útil,
    no se persisten como hallazgos XSS.
    """
    raw_findings = _coerce_findings_list(summary_json)
    normalized: List[Dict[str, Any]] = []
    finding_order = 0

    for item in raw_findings:
        if isinstance(item, dict):
            if not item:
                continue

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

        if not _has_meaningful_content(
            param_name=param_name,
            payload=payload,
            evidence=evidence,
            severity=severity,
            source_type=source_type,
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

    return _deduplicate_findings(normalized)