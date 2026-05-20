"""
scanner_service.py
- Servicio reutilizable para ejecutar una evaluación completa DASTXH.
- Esta versión queda adaptada al esquema normalizado v9.

Objetivos de esta versión:
- conservar flujo síncrono y background
- usar un flujo estándar único: evaluación profunda controlada
- mantener scan_profile="profundo" como dato técnico fijo en BD
- habilitar hsecscan como parte del flujo estándar
- ejecutar primero las herramientas de escaneo y después las tareas IA
- persistir cookies observadas y ejecutar análisis por reglas + IA:
  * risk_level
  * cwe_mappings
  * interpretation_humana
  * recommended_action
- persistir hsecscan como segunda capa:
  * salida cruda en hsecscan.txt
  * salida estructurada en hsecscan.json
  * salida estructurada en hsecscan_results.structured_json
  * resumen en hsecscan_results.summary_json
  * checks normalizados en hsecscan_checks
- traducir con IA campos específicos de hsecscan:
  * security_description -> security_description_es
  * recommendations      -> recommendations_es
  * cwe                  -> cwe_es
- persistir hallazgos XSS estructurados
- preparar agrupación XSS para IA
- intentar interpretación XSS con backend compatible con OpenAI
- registrar claramente en run_meta.json:
  * estado de Dalfox
  * estado de interpretación IA de cookies
  * resumen estructurado de hsecscan
  * estado de traducción IA de hsecscan
  * total de hallazgos XSS estructurados
  * total de hallazgos válidos para IA
  * hallazgos excluidos por estar vacíos/no útiles
  * modo individual o agrupado
  * estado de interpretación IA XSS
  * error o éxito parcial cuando aplique
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import db as db_layer
from config import (
    ARTIFACT_TYPE_DALFOX_JSON,
    ARTIFACT_TYPE_DALFOX_TXT,
    ARTIFACT_TYPE_HEADERS_JSON,
    ARTIFACT_TYPE_HSECSCAN_JSON,
    ARTIFACT_TYPE_HSECSCAN_TXT,
    ARTIFACT_TYPE_REPORT_HTML,
    ARTIFACT_TYPE_REPORT_MD,
    ARTIFACT_TYPE_RUN_META_JSON,
    DALFOX_JSON,
    DALFOX_TXT,
    HEADERS_JSON,
    HSECSCAN_JSON,
    HSECSCAN_TXT,
    MIME_APPLICATION_JSON,
    MIME_TEXT_HTML,
    MIME_TEXT_MARKDOWN,
    MIME_TEXT_PLAIN,
    REPORT_HTML,
    REPORT_MD,
    RUN_META_JSON,
)
from report import build_report_html, build_report_md
from services.cookie_ai_service import interpret_cookie_checks_with_ai
from services.hsecscan_ai_translation_service import translate_hsecscan_checks_with_ai
from services.xss_ai_service import build_xss_ai_input_payload
from services.xss_model_runner_service import (
    interpret_xss_groups_with_ai,
    merge_xss_ai_interpretations,
)
from tools.curl_custom import curl_fetch_headers, evaluate_headers_and_cookies
from tools.dalfox_tool import extract_structured_findings, read_summary, run_dalfox
from tools.hsecscan_tool import parse_hsecscan_output, run_hsecscan
from utils import ensure_dir, safe_read_text, ts_folder, utc_now, write_json


# ==========================================================
# FLUJO ESTÁNDAR DASTXH
# ==========================================================

STANDARD_SCAN_PROFILE = "profundo"
STANDARD_ENABLE_HSECSCAN = True
STANDARD_FLOW_LABEL = "evaluacion_profunda_controlada"


# ==========================================================
# CONTEXTO INTERNO DE EJECUCIÓN
# ==========================================================

@dataclass
class ScanContext:
    """
    Estructura interna que agrupa los datos mínimos necesarios
    para ejecutar el pipeline sin depender del request web.
    """
    execution_id: int
    target_url: str
    request_source: str
    scan_profile: str
    enable_hsecscan: bool
    started_at: datetime
    reports_root: Path
    report_dir: Path
    report_dir_logical: str
    run_meta_path: Path


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _file_size_or_none(path: Path) -> Optional[int]:
    """
    Devuelve el tamaño del archivo en bytes si existe.
    Si no existe o falla, devuelve None.
    """
    try:
        if path.exists() and path.is_file():
            return int(path.stat().st_size)
    except Exception:
        return None

    return None


def _register_file_artifact(
    dsn: str,
    execution_id: int,
    reports_root: Path,
    file_path: Path,
    artifact_type: str,
    mime_type: Optional[str],
) -> None:
    """
    Registra un archivo físico como artifact en la tabla artifacts.
    """
    if not file_path.exists() or not file_path.is_file():
        return

    try:
        relative_path = str(file_path.relative_to(reports_root.parent)).replace("\\", "/")
    except Exception:
        relative_path = file_path.name

    db_layer.register_artifact(
        dsn=dsn,
        execution_id=execution_id,
        artifact_type=artifact_type,
        file_name=file_path.name,
        relative_path=relative_path,
        mime_type=mime_type,
        size_bytes=_file_size_or_none(file_path),
    )


def _append_artifact_name(run_meta: Dict[str, Any], file_name: str) -> None:
    """
    Agrega un artifact al run_meta solo si todavía no existe.
    """
    artifacts = run_meta.setdefault("artifacts", [])

    if file_name and file_name not in artifacts:
        artifacts.append(file_name)


def _build_unique_run_id(reports_root: Path, started: datetime) -> str:
    """
    Genera un identificador de carpeta único basado en timestamp.
    """
    base_run_id = ts_folder(started)
    candidate = base_run_id
    counter = 1

    while (reports_root / candidate).exists():
        counter += 1
        candidate = f"{base_run_id}_{counter:02d}"

    return candidate


def _resolve_standard_scan_profile(scan_profile: Optional[str]) -> str:
    """
    Devuelve el perfil técnico estándar usado por DASTXH.

    Decisión actual:
    - ya no se expone perfil al usuario;
    - el flujo del prototipo es profundo controlado;
    - se conserva el campo scan_profile en BD con valor fijo "profundo"
      para no romper historial, vistas ni consultas existentes.
    """
    return STANDARD_SCAN_PROFILE


def _resolve_enable_hsecscan(
    scan_profile: str,
    enable_hsecscan: Optional[bool],
) -> bool:
    """
    Define si hsecscan debe ejecutarse.

    Decisión actual:
    - hsecscan forma parte del flujo estándar profundo controlado;
    - se habilita siempre desde el backend;
    - enable_hsecscan se conserva como parámetro por compatibilidad,
      pero ya no gobierna la experiencia del usuario.
    """
    return STANDARD_ENABLE_HSECSCAN


def _assign_stable_group_order(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Garantiza que cada entrada preparada para IA tenga group_order estable.

    xss_ai_service.py ya debería asignarlo, pero esta defensa evita que la BD,
    run_meta.json y la respuesta de IA se desalineen si alguna entrada llegara
    sin numeración.
    """
    prepared_entries: list[dict[str, Any]] = []

    for index, raw_entry in enumerate(entries or [], start=1):
        entry = dict(raw_entry)

        try:
            group_order = int(entry.get("group_order") or index)
        except Exception:
            group_order = index

        entry["group_order"] = group_order
        prepared_entries.append(entry)

    return prepared_entries


def _build_xss_ai_preparation_meta(
    xss_ai_input_payload: Dict[str, Any],
    entries: list[dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construye el bloque xss_ai_preparation para run_meta.json.
    """
    return {
        "enabled": True,
        "mode": xss_ai_input_payload.get("mode"),
        "total_findings": xss_ai_input_payload.get("total_findings"),
        "total_valid_findings": xss_ai_input_payload.get("total_valid_findings"),
        "excluded_findings": xss_ai_input_payload.get("excluded_findings"),
        "total_groups": xss_ai_input_payload.get("total_groups"),
        "entries": entries,
    }


def _build_xss_ai_interpretation_meta(ai_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye el bloque xss_ai_interpretation para run_meta.json.
    """
    return {
        "enabled": ai_result.get("enabled"),
        "ok": ai_result.get("ok"),
        "skipped": ai_result.get("skipped"),
        "model_name": ai_result.get("model_name"),
        "error": ai_result.get("error"),
        "groups_interpreted": len(ai_result.get("groups", []) or []),
    }


def _build_skipped_ai_result(model_name: Optional[str], reason: str) -> Dict[str, Any]:
    """
    Construye una respuesta interna cuando no hay grupos válidos para enviar a IA.
    """
    return {
        "enabled": True,
        "ok": False,
        "skipped": True,
        "model_name": model_name,
        "groups": [],
        "error": reason,
    }
# ==========================================================
# HELPERS HSECSCAN
# ==========================================================

def _safe_parse_hsecscan_output(raw_output: str) -> Dict[str, Any]:
    """
    Ejecuta el parser de hsecscan sin permitir que un error de parseo
    detenga todo el escaneo.

    Si el parser falla, se devuelve un objeto estructurado con ok=False.
    """
    try:
        return parse_hsecscan_output(raw_output)
    except Exception as exc:
        return {
            "ok": False,
            "response_info": {
                "url": None,
                "status_code": None,
                "headers": [],
            },
            "observed_headers": [],
            "missing_headers": [],
            "summary": {
                "status_code": None,
                "response_headers_count": 0,
                "observed_security_headers_count": 0,
                "missing_security_headers_count": 0,
                "total_hsecscan_records": 0,
                "missing_header_names": [],
                "observed_header_names": [],
                "has_set_cookie": False,
                "has_server_disclosure": False,
                "has_content_security_policy": False,
                "has_x_frame_options": False,
                "has_x_content_type_options": False,
                "has_strict_transport_security": False,
            },
            "parse_warnings": [
                f"No fue posible parsear la salida de hsecscan: {str(exc)}"
            ],
        }


def _build_hsecscan_meta(
    hsecscan_rc: Optional[int],
    hsecscan_structured: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construye un resumen pequeño de hsecscan para run_meta.json.
    """
    if not hsecscan_structured:
        return {
            "enabled": False,
            "tool_rc": hsecscan_rc,
            "ok": False,
            "summary": None,
            "parse_warnings": [],
        }

    return {
        "enabled": True,
        "tool_rc": hsecscan_rc,
        "ok": hsecscan_structured.get("ok"),
        "summary": hsecscan_structured.get("summary"),
        "parse_warnings": hsecscan_structured.get("parse_warnings", []),
    }


def _build_hsecscan_translation_failure_meta(error: str) -> Dict[str, Any]:
    """
    Construye metadata cuando la traducción IA de hsecscan falla.

    Importante:
    - La traducción es apoyo visual.
    - Si falla, el escaneo principal no debe fallar.
    """
    return {
        "enabled": True,
        "ok": False,
        "skipped": False,
        "requested_checks": 0,
        "candidate_checks": 0,
        "translated_checks": 0,
        "persisted_translations": 0,
        "errors": [
            {
                "batch_index": None,
                "items": 0,
                "translated_items": 0,
                "error": error,
            }
        ],
    }


def _run_hsecscan_ai_translation(
    dsn: str,
    execution_id: int,
) -> Dict[str, Any]:
    """
    Ejecuta la traducción IA sobre checks de hsecscan ya guardados en BD.

    Flujo:
    1. Lee hsecscan_checks persistidos.
    2. Envía los campos traducibles al modelo.
    3. Actualiza columnas *_es en hsecscan_checks.
    4. Devuelve metadata para run_meta.json.

    Si algo falla, no interrumpe el escaneo.
    """
    try:
        checks_for_translation = db_layer.list_hsecscan_checks_for_translation(
            dsn=dsn,
            execution_id=execution_id,
        )

        translations, translation_meta = translate_hsecscan_checks_with_ai(
            checks_for_translation
        )

        if translations:
            db_layer.update_hsecscan_check_translations(
                dsn=dsn,
                execution_id=execution_id,
                translations=translations,
                model_name=translation_meta.get("model_name"),
            )

        translation_meta["ok"] = bool(translations) and not bool(translation_meta.get("errors"))
        translation_meta["persisted_translations"] = len(translations or [])

        if not translations and not translation_meta.get("errors"):
            translation_meta["ok"] = False
            translation_meta.setdefault("skipped", True)

        return translation_meta

    except Exception as exc:
        return _build_hsecscan_translation_failure_meta(str(exc))


# ==========================================================
# HELPERS COOKIES
# ==========================================================

def _build_cookie_ai_failure_meta(error: str) -> Dict[str, Any]:
    """
    Construye metadata cuando falla la interpretación IA/reglas de cookies.

    Importante:
    - El análisis de cookies es una capa de explicación.
    - Si falla, el escaneo principal no debe fallar.
    """
    return {
        "enabled": True,
        "ok": False,
        "skipped": False,
        "requested_cookies": 0,
        "candidate_cookies": 0,
        "interpreted_cookies": 0,
        "interpreted_by_ai": 0,
        "persisted_interpretations": 0,
        "rules_fallback_used": False,
        "errors": [
            {
                "cookie_check_id": None,
                "error": error,
            }
        ],
    }


def _run_cookie_ai_interpretation(
    dsn: str,
    execution_id: int,
) -> Dict[str, Any]:
    """
    Ejecuta análisis de cookies con reglas + IA.

    Flujo:
    1. Lee cookies observadas desde cookie_checks.
    2. Aplica reglas internas alineadas con OWASP + mapeo CWE.
    3. Usa IA para redactar interpretación y recomendación breve.
    4. Persiste risk_level, cwe_mappings, interpretation_humana y recommended_action.
    5. Devuelve metadata para run_meta.json.

    Si la IA falla, cookie_ai_service.py devuelve fallback por reglas.
    Si algo falla aquí, no se interrumpe el escaneo.
    """
    try:
        cookies_for_interpretation = db_layer.list_cookie_checks_for_interpretation(
            dsn=dsn,
            execution_id=execution_id,
        )

        interpretations, cookie_meta = interpret_cookie_checks_with_ai(
            cookies_for_interpretation
        )

        if interpretations:
            db_layer.update_cookie_check_interpretations(
                dsn=dsn,
                execution_id=execution_id,
                interpretations=interpretations,
                model_name=cookie_meta.get("model_name"),
            )

        cookie_meta["persisted_interpretations"] = len(interpretations or [])

        if interpretations and not cookie_meta.get("errors"):
            cookie_meta["ok"] = True
        elif interpretations and cookie_meta.get("errors"):
            cookie_meta["ok"] = False
            cookie_meta["partial_success"] = True
        else:
            cookie_meta["ok"] = False

        if not interpretations and not cookie_meta.get("errors"):
            cookie_meta.setdefault("skipped", True)

        return cookie_meta

    except Exception as exc:
        return _build_cookie_ai_failure_meta(str(exc))


# ==========================================================
# PREPARACIÓN DE CONTEXTO
# ==========================================================

def _prepare_scan_context(
    dsn: str,
    workdir: Path,
    url: str,
    request_source: str,
    scan_profile: str,
    enable_hsecscan: Optional[bool],
) -> Tuple[ScanContext, Dict[str, Any]]:
    """
    Prepara la estructura mínima de una nueva ejecución.

    Aunque el parámetro scan_profile se conserva para compatibilidad con
    llamadas internas anteriores, el valor efectivo se normaliza siempre
    a "profundo".
    """
    started = utc_now()

    ensure_dir(workdir)

    reports_root = workdir / "reports"
    ensure_dir(reports_root)

    run_id = _build_unique_run_id(reports_root, started)
    report_dir = reports_root / run_id
    ensure_dir(report_dir)

    report_dir_logical = f"/work/reports/{run_id}"

    resolved_scan_profile = _resolve_standard_scan_profile(scan_profile)
    enable_hsecscan_resolved = _resolve_enable_hsecscan(
        scan_profile=resolved_scan_profile,
        enable_hsecscan=enable_hsecscan,
    )

    execution_id = db_layer.insert_execution(
        dsn=dsn,
        target_url=url,
        request_source=request_source,
        report_dir=report_dir_logical,
        status="initiated",
        scan_profile=resolved_scan_profile,
        enable_hsecscan=enable_hsecscan_resolved,
        urls_ingresadas=1,
        urls_evaluadas=0,
    )

    context = ScanContext(
        execution_id=execution_id,
        target_url=url,
        request_source=request_source,
        scan_profile=resolved_scan_profile,
        enable_hsecscan=enable_hsecscan_resolved,
        started_at=started,
        reports_root=reports_root,
        report_dir=report_dir,
        report_dir_logical=report_dir_logical,
        run_meta_path=report_dir / RUN_META_JSON,
    )

    run_meta: Dict[str, Any] = {
        "target_url": url,
        "started_at": started.isoformat(),
        "finished_at": None,
        "status": "initiated",
        "execution_id": execution_id,
        "request_source": request_source,
        "scan_profile": resolved_scan_profile,
        "flow_mode": STANDARD_FLOW_LABEL,
        "enable_hsecscan": enable_hsecscan_resolved,
        "errors": [],
        "report_dir": report_dir_logical,
        "artifacts": [],
    }

    write_json(context.run_meta_path, run_meta)

    return context, run_meta
# ==========================================================
# PIPELINE PRINCIPAL
# ==========================================================

def _run_scan_pipeline(
    dsn: str,
    context: ScanContext,
    timeout_s: int,
    run_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Ejecuta el pipeline completo usando un contexto ya preparado.
    """
    execution_id = context.execution_id
    url = context.target_url
    request_source = context.request_source
    scan_profile = context.scan_profile
    enable_hsecscan = context.enable_hsecscan
    report_dir = context.report_dir
    report_dir_logical = context.report_dir_logical
    reports_root = context.reports_root
    run_meta_path = context.run_meta_path

    try:
        # --------------------------------------------------
        # Marcar ejecución como running
        # --------------------------------------------------
        db_layer.update_execution_running(dsn, execution_id)
        run_meta["status"] = "running"
        write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # CAPA 1: curl custom
        # --------------------------------------------------
        raw_last_block, raw_headers_json = curl_fetch_headers(url, timeout_s)
        hdr_eval = evaluate_headers_and_cookies(raw_headers_json)

        headers_json_path = report_dir / HEADERS_JSON
        write_json(
            headers_json_path,
            {
                "target_url": url,
                "evaluation": hdr_eval,
                "raw": raw_headers_json,
                "raw_last_block": raw_last_block,
            },
        )

        db_layer.insert_header_results(
            dsn=dsn,
            execution_id=execution_id,
            hdr_eval=hdr_eval,
            raw_headers_json=raw_headers_json,
        )

        # --------------------------------------------------
        # IA DE COOKIES
        # --------------------------------------------------
        # Se pospone hasta después de Dalfox.
        # Motivo:
        # - primero se cierran las herramientas de escaneo;
        # - después se ejecutan las capas de enriquecimiento con IA.
        cookie_ai_interpretation_meta: Optional[Dict[str, Any]] = None

        # --------------------------------------------------
        # CAPA 2: hsecscan
        # --------------------------------------------------
        hsecscan_txt_path = report_dir / HSECSCAN_TXT
        hsecscan_json_path = report_dir / HSECSCAN_JSON
        hsecscan_rc: Optional[int] = None
        hsecscan_structured: Optional[Dict[str, Any]] = None
        hsecscan_json_document: Optional[Dict[str, Any]] = None
        hsecscan_ai_translation_meta: Optional[Dict[str, Any]] = None

        if enable_hsecscan:
            hsecscan_rc, hsecscan_out = run_hsecscan(url)

            # Evidencia cruda original.
            hsecscan_txt_path.write_text(
                hsecscan_out,
                encoding="utf-8",
                errors="replace",
            )

            # Evidencia estructurada.
            hsecscan_structured = _safe_parse_hsecscan_output(hsecscan_out)

            hsecscan_json_document = {
                "target_url": url,
                "tool_rc": hsecscan_rc,
                "parsed_at": utc_now().isoformat(),
                "structured": hsecscan_structured,
            }

            write_json(
                hsecscan_json_path,
                hsecscan_json_document,
            )

            # Persistencia v9:
            # - raw_output queda igual que antes
            # - structured_json guarda el documento completo
            # - summary_json guarda el resumen útil
            # - hsecscan_checks se llena desde observed_headers + missing_headers
            # - columnas *_es quedan disponibles para traducción IA posterior
            db_layer.insert_hsecscan_results(
                dsn=dsn,
                execution_id=execution_id,
                tool_rc=hsecscan_rc,
                raw_output=hsecscan_out,
                structured_json=hsecscan_json_document,
                summary_json=hsecscan_structured.get("summary")
                if isinstance(hsecscan_structured, dict)
                else None,
                hsecscan_checks=(
                    (hsecscan_structured.get("observed_headers", []) or [])
                    + (hsecscan_structured.get("missing_headers", []) or [])
                    if isinstance(hsecscan_structured, dict)
                    else []
                ),
            )

            run_meta["hsecscan_structured"] = _build_hsecscan_meta(
                hsecscan_rc=hsecscan_rc,
                hsecscan_structured=hsecscan_structured,
            )

            write_json(run_meta_path, run_meta)

            # --------------------------------------------------
            # TRADUCCIÓN IA DE HSECSCAN
            # --------------------------------------------------
            # Se pospone hasta después de Dalfox.
            # Motivo:
            # - hsecscan ya queda persistido como evidencia técnica;
            # - Dalfox no debe esperar a que termine la traducción IA.
            hsecscan_ai_translation_meta = None

        # --------------------------------------------------
        # CAPA 3: Dalfox / XSS
        # --------------------------------------------------
        dalfox_json_path = report_dir / DALFOX_JSON
        dalfox_txt_path = report_dir / DALFOX_TXT

        run_meta["dalfox_status"] = {
            "status": "running",
            "started_at": utc_now().isoformat(),
            "profile": scan_profile,
            "flow_mode": STANDARD_FLOW_LABEL,
        }
        write_json(run_meta_path, run_meta)

        dalfox_rc, dalfox_raw = run_dalfox(
            url=url,
            timeout_s=timeout_s,
            out_json=dalfox_json_path,
            scan_profile=scan_profile,
        )

        dalfox_txt_path.write_text(dalfox_raw, encoding="utf-8", errors="replace")

        raw_findings_count, summary_json = read_summary(dalfox_json_path)

        run_meta["dalfox_status"] = {
            "status": "finished",
            "finished_at": utc_now().isoformat(),
            "tool_rc": dalfox_rc,
            "raw_findings_count": raw_findings_count,
            "profile": scan_profile,
            "flow_mode": STANDARD_FLOW_LABEL,
        }

        structured_findings = extract_structured_findings(
            summary_json=summary_json,
            fallback_target_url=url,
        )

        effective_findings_count = len(structured_findings)
        run_meta["dalfox_status"]["structured_findings_count"] = effective_findings_count
        write_json(run_meta_path, run_meta)

        db_layer.insert_xss_results(
            dsn=dsn,
            execution_id=execution_id,
            tool_rc=dalfox_rc,
            findings_count=effective_findings_count,
            summary_json=summary_json,
            raw_output=safe_read_text(dalfox_txt_path),
            xss_findings=structured_findings,
        )

        # --------------------------------------------------
        # PREPARACIÓN XSS PARA IA
        # --------------------------------------------------
        xss_ai_input_payload = build_xss_ai_input_payload(structured_findings)

        prepared_entries = _assign_stable_group_order(
            xss_ai_input_payload.get("entries", []) or []
        )

        xss_ai_input_payload["entries"] = prepared_entries

        # Guardar grupos preparados en BD.
        db_layer.insert_xss_ai_groups(
            dsn=dsn,
            execution_id=execution_id,
            xss_ai_payload=xss_ai_input_payload,
        )

        # Guardar preparación antes de llamar a IA.
        run_meta["xss_ai_preparation"] = _build_xss_ai_preparation_meta(
            xss_ai_input_payload=xss_ai_input_payload,
            entries=prepared_entries,
        )
        write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # INTERPRETACIÓN DE COOKIES CON REGLAS + IA
        # --------------------------------------------------
        # Esta capa usa como base las cookies ya persistidas por curl.
        # Se ejecuta después de Dalfox para no retrasar la fase XSS.
        cookie_ai_interpretation_meta = _run_cookie_ai_interpretation(
            dsn=dsn,
            execution_id=execution_id,
        )

        run_meta["cookie_ai_interpretation"] = cookie_ai_interpretation_meta
        write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # TRADUCCIÓN IA DE HSECSCAN
        # --------------------------------------------------
        # Esta traducción es solo apoyo lingüístico para GUI.
        # Se ejecuta después de Dalfox para que la fase XSS no quede
        # bloqueada por traducciones largas o respuestas JSON inválidas.
        if enable_hsecscan:
            hsecscan_ai_translation_meta = _run_hsecscan_ai_translation(
                dsn=dsn,
                execution_id=execution_id,
            )

            run_meta["hsecscan_ai_translation"] = hsecscan_ai_translation_meta
            write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # INTERPRETACIÓN IA XSS
        # --------------------------------------------------
        if prepared_entries:
            ai_result = interpret_xss_groups_with_ai(xss_ai_input_payload)
        else:
            ai_result = _build_skipped_ai_result(
                model_name=None,
                reason="No hay grupos XSS válidos para interpretar con IA.",
            )

        # Por defecto usamos los grupos preparados.
        enriched_xss_ai_groups = prepared_entries

        if ai_result.get("ok"):
            interpreted_groups = ai_result.get("groups", []) or []

            db_layer.update_xss_ai_group_interpretations(
                dsn=dsn,
                execution_id=execution_id,
                interpretations=interpreted_groups,
                model_name=ai_result.get("model_name"),
            )

            enriched_xss_ai_groups = merge_xss_ai_interpretations(
                prepared_entries=prepared_entries,
                interpreted_groups=interpreted_groups,
                model_name=ai_result.get("model_name"),
            )

        # Actualizar run_meta con entradas enriquecidas.
        run_meta["xss_ai_preparation"] = _build_xss_ai_preparation_meta(
            xss_ai_input_payload=xss_ai_input_payload,
            entries=enriched_xss_ai_groups,
        )

        run_meta["xss_ai_interpretation"] = _build_xss_ai_interpretation_meta(ai_result)

        write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # REPORTES / ARTIFACTS ACTUALES
        # --------------------------------------------------
        report_md = build_report_md(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            hsecscan_filename=HSECSCAN_TXT if enable_hsecscan else None,
            dalfox_json_filename=DALFOX_JSON,
            dalfox_txt_filename=DALFOX_TXT,
            xss_ai_groups=enriched_xss_ai_groups,
        )

        report_md_path = report_dir / REPORT_MD
        report_md_path.write_text(report_md, encoding="utf-8", errors="replace")

        report_html = build_report_html(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            hsecscan_filename=HSECSCAN_TXT if enable_hsecscan else None,
            dalfox_json_filename=DALFOX_JSON,
            dalfox_txt_filename=DALFOX_TXT,
            xss_ai_groups=enriched_xss_ai_groups,
        )

        report_html_path = report_dir / REPORT_HTML
        report_html_path.write_text(report_html, encoding="utf-8", errors="replace")
        # --------------------------------------------------
        # Registrar artifacts
        # --------------------------------------------------
        artifact_specs = [
            (headers_json_path, ARTIFACT_TYPE_HEADERS_JSON, MIME_APPLICATION_JSON),
            (dalfox_json_path, ARTIFACT_TYPE_DALFOX_JSON, MIME_APPLICATION_JSON),
            (dalfox_txt_path, ARTIFACT_TYPE_DALFOX_TXT, MIME_TEXT_PLAIN),
            (report_md_path, ARTIFACT_TYPE_REPORT_MD, MIME_TEXT_MARKDOWN),
            (report_html_path, ARTIFACT_TYPE_REPORT_HTML, MIME_TEXT_HTML),
        ]

        if enable_hsecscan and hsecscan_txt_path.exists():
            artifact_specs.insert(
                1,
                (hsecscan_txt_path, ARTIFACT_TYPE_HSECSCAN_TXT, MIME_TEXT_PLAIN),
            )

        if enable_hsecscan and hsecscan_json_path.exists():
            artifact_specs.insert(
                2,
                (hsecscan_json_path, ARTIFACT_TYPE_HSECSCAN_JSON, MIME_APPLICATION_JSON),
            )

        for file_path, artifact_type, mime_type in artifact_specs:
            _register_file_artifact(
                dsn=dsn,
                execution_id=execution_id,
                reports_root=reports_root,
                file_path=file_path,
                artifact_type=artifact_type,
                mime_type=mime_type,
            )

            if file_path.exists():
                _append_artifact_name(run_meta, file_path.name)

        # --------------------------------------------------
        # Cierre exitoso
        # --------------------------------------------------
        db_layer.update_execution_finished(
            dsn=dsn,
            execution_id=execution_id,
            ok=True,
            error_message=None,
            urls_evaluadas=1,
        )

        finished = utc_now()
        run_meta["finished_at"] = finished.isoformat()
        run_meta["status"] = "finished"
        run_meta["flow_mode"] = STANDARD_FLOW_LABEL
        run_meta["cumplimiento_pct"] = hdr_eval.get("cumplimiento_pct")
        run_meta["http_score"] = hdr_eval.get("http_score")
        run_meta["http_grade"] = hdr_eval.get("http_grade")
        run_meta["cookie_ai_interpretation"] = cookie_ai_interpretation_meta
        run_meta["hsecscan_rc"] = hsecscan_rc
        run_meta["hsecscan_structured"] = _build_hsecscan_meta(
            hsecscan_rc=hsecscan_rc,
            hsecscan_structured=hsecscan_structured,
        )

        if enable_hsecscan:
            run_meta["hsecscan_ai_translation"] = hsecscan_ai_translation_meta

        run_meta["dalfox_rc"] = dalfox_rc
        run_meta["findings_count"] = effective_findings_count
        run_meta["xss_findings_structured_count"] = len(structured_findings)
        run_meta["xss_ai_valid_findings_count"] = xss_ai_input_payload.get("total_valid_findings")
        run_meta["xss_ai_excluded_findings_count"] = xss_ai_input_payload.get("excluded_findings")

        write_json(run_meta_path, run_meta)

        _register_file_artifact(
            dsn=dsn,
            execution_id=execution_id,
            reports_root=reports_root,
            file_path=run_meta_path,
            artifact_type=ARTIFACT_TYPE_RUN_META_JSON,
            mime_type=MIME_APPLICATION_JSON,
        )

        _append_artifact_name(run_meta, RUN_META_JSON)
        write_json(run_meta_path, run_meta)

        return {
            "ok": True,
            "execution_id": execution_id,
            "status": "finished",
            "target_url": url,
            "request_source": request_source,
            "scan_profile": scan_profile,
            "flow_mode": STANDARD_FLOW_LABEL,
            "enable_hsecscan": enable_hsecscan,
            "report_dir": report_dir_logical,
            "report_md": f"{report_dir_logical}/{REPORT_MD}",
            "report_html": f"{report_dir_logical}/{REPORT_HTML}",
            "compliance_pct": hdr_eval.get("cumplimiento_pct"),
            "http_score": hdr_eval.get("http_score"),
            "http_grade": hdr_eval.get("http_grade"),
            "cookie_ai_interpretation": cookie_ai_interpretation_meta,
            "hsecscan_rc": hsecscan_rc,
            "hsecscan_structured_summary": (
                hsecscan_structured.get("summary")
                if isinstance(hsecscan_structured, dict)
                else None
            ),
            "hsecscan_ai_translation": hsecscan_ai_translation_meta,
            "dalfox_rc": dalfox_rc,
            "findings_count": effective_findings_count,
            "xss_ai_mode": xss_ai_input_payload.get("mode"),
            "xss_ai_total_groups": xss_ai_input_payload.get("total_groups"),
            "xss_ai_total_valid_findings": xss_ai_input_payload.get("total_valid_findings"),
            "xss_ai_excluded_findings": xss_ai_input_payload.get("excluded_findings"),
            "xss_ai_interpretation_ok": ai_result.get("ok"),
            "xss_ai_interpretation_error": ai_result.get("error"),
            "artifacts": run_meta["artifacts"],
        }

    except Exception as exc:
        err = str(exc)
        finished = utc_now()

        run_meta["status"] = "failed"
        run_meta["finished_at"] = finished.isoformat()
        run_meta["flow_mode"] = STANDARD_FLOW_LABEL
        run_meta["errors"].append(err)

        write_json(run_meta_path, run_meta)

        try:
            db_layer.update_execution_finished(
                dsn=dsn,
                execution_id=execution_id,
                ok=False,
                error_message=err[:8000],
                urls_evaluadas=0,
            )

            _register_file_artifact(
                dsn=dsn,
                execution_id=execution_id,
                reports_root=reports_root,
                file_path=run_meta_path,
                artifact_type=ARTIFACT_TYPE_RUN_META_JSON,
                mime_type=MIME_APPLICATION_JSON,
            )

            _append_artifact_name(run_meta, RUN_META_JSON)
            write_json(run_meta_path, run_meta)
        except Exception:
            pass

        return {
            "ok": False,
            "execution_id": execution_id,
            "status": "failed",
            "target_url": url,
            "request_source": request_source,
            "scan_profile": scan_profile,
            "flow_mode": STANDARD_FLOW_LABEL,
            "enable_hsecscan": enable_hsecscan,
            "report_dir": report_dir_logical,
            "error": err,
            "artifacts": run_meta.get("artifacts", []),
        }


def _background_scan_worker(
    dsn: str,
    context: ScanContext,
    timeout_s: int,
    run_meta: Dict[str, Any],
) -> None:
    """
    Worker interno para ejecutar el pipeline en segundo plano.
    """
    _run_scan_pipeline(
        dsn=dsn,
        context=context,
        timeout_s=timeout_s,
        run_meta=run_meta,
    )


# ==========================================================
# SERVICIO PÚBLICO: MODO SÍNCRONO
# ==========================================================

def execute_scan(
    dsn: str,
    workdir: Path,
    url: str,
    timeout_s: int,
    request_source: str = "cli",
    scan_profile: str = STANDARD_SCAN_PROFILE,
    enable_hsecscan: Optional[bool] = STANDARD_ENABLE_HSECSCAN,
) -> Dict[str, Any]:
    """
    Ejecuta una evaluación completa de forma síncrona.

    Nota:
    - scan_profile y enable_hsecscan se conservan como parámetros para
      compatibilidad, pero el flujo efectivo se normaliza internamente
      a evaluación profunda controlada.
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
        scan_profile=scan_profile,
        enable_hsecscan=enable_hsecscan,
    )

    return _run_scan_pipeline(
        dsn=dsn,
        context=context,
        timeout_s=timeout_s,
        run_meta=run_meta,
    )


# ==========================================================
# SERVICIO PÚBLICO: MODO ASÍNCRONO / BACKGROUND
# ==========================================================

def start_scan_in_background(
    dsn: str,
    workdir: Path,
    url: str,
    timeout_s: int,
    request_source: str = "web",
    scan_profile: str = STANDARD_SCAN_PROFILE,
    enable_hsecscan: Optional[bool] = STANDARD_ENABLE_HSECSCAN,
) -> Dict[str, Any]:
    """
    Inicia un escaneo en segundo plano y devuelve inmediatamente
    los datos mínimos de seguimiento.

    Nota:
    - desde la GUI ya no existe selector de perfil;
    - el backend mantiene scan_profile="profundo" como valor técnico fijo.
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
        scan_profile=scan_profile,
        enable_hsecscan=enable_hsecscan,
    )

    worker = threading.Thread(
        target=_background_scan_worker,
        kwargs={
            "dsn": dsn,
            "context": context,
            "timeout_s": timeout_s,
            "run_meta": run_meta,
        },
        name=f"dastxh-scan-{context.execution_id}",
        daemon=True,
    )
    worker.start()

    return {
        "ok": True,
        "accepted": True,
        "execution_id": context.execution_id,
        "status": "initiated",
        "target_url": context.target_url,
        "request_source": context.request_source,
        "scan_profile": context.scan_profile,
        "flow_mode": STANDARD_FLOW_LABEL,
        "enable_hsecscan": context.enable_hsecscan,
        "report_dir": context.report_dir_logical,
    }