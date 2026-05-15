"""
db.py
- Acceso a PostgreSQL usando psycopg (psycopg3).
- Adaptado al esquema normalizado v7.

Responsabilidades:
- ejecutar operaciones CRUD de persistencia
- guardar resultados HTTP
- guardar resultados hsecscan crudos y estructurados
- guardar checks normalizados de hsecscan
- guardar resultados XSS
- guardar agrupación XSS preparada para IA
- guardar interpretaciones generadas por IA
- exponer consultas de historial y detalle

Fase 3:
- construir comparación derivada entre:
  * curl custom / http_tests
  * hsecscan / hsecscan_checks

Ajuste actual:
- el conteo visual de Hallazgos XSS ahora usa únicamente las filas válidas
  que realmente se muestran en la tabla XSS.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from utils import utc_now


# ==========================================================
# CONEXIÓN Y SALUD DE BASE DE DATOS
# ==========================================================

def connect(dsn: str) -> Connection:
    """
    Crea y devuelve una conexión a PostgreSQL.
    """
    return psycopg.connect(dsn, row_factory=dict_row)


def ping_db(dsn: str) -> None:
    """
    Verificación rápida de conectividad con PostgreSQL.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.commit()


# ==========================================================
# HELPERS PRIVADOS DE NORMALIZACIÓN
# ==========================================================

def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a texto JSON para insertarlo como json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _build_header_details_if_missing(hdr_eval: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Si hdr_eval no trae header_details, los reconstruye usando present/missing.
    """
    header_details = hdr_eval.get("header_details")

    if isinstance(header_details, list):
        return header_details

    present = set(hdr_eval.get("present", []) or [])
    missing = set(hdr_eval.get("missing", []) or [])

    combined = list(present) + [h for h in missing if h not in present]

    result: List[Dict[str, Any]] = []

    for header_name in combined:
        result.append(
            {
                "header_name": str(header_name),
                "is_present": header_name in present,
                "header_value": None,
            }
        )

    return result


def _normalize_cookie_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza un registro de cookie para aceptar tanto la forma vieja
    como la nueva.
    """
    cookie_raw = item.get("cookie_raw")

    if cookie_raw is None:
        cookie_raw = item.get("cookie", "")

    cookie_name = item.get("cookie_name")

    samesite_present = item.get("samesite_present")

    if samesite_present is None:
        samesite_present = bool(item.get("samesite"))

    return {
        "cookie_name": cookie_name,
        "cookie_raw": str(cookie_raw or ""),
        "secure": bool(item.get("secure")),
        "httponly": bool(item.get("httponly")),
        "samesite_present": bool(samesite_present),
        "samesite_value": item.get("samesite_value"),
    }


def _normalize_http_test_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza una prueba HTTP detallada antes de persistirla.
    """
    return {
        "test_id": str(item.get("test_id", "") or "").strip(),
        "name": str(item.get("name", "") or "").strip(),
        "category": str(item.get("category", "") or "").strip(),
        "status": str(item.get("status", "info") or "info").strip(),
        "score_delta": int(item.get("score_delta", 0) or 0),
        "reason": str(item.get("reason", "") or "").strip(),
        "recommendation": str(item.get("recommendation", "") or "").strip(),
        "header_name": item.get("header_name"),
        "header_value": item.get("header_value"),
    }


def _normalize_xss_ai_group_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza una entrada agrupada XSS antes de persistirla.
    """
    entry_type = str(item.get("entry_type", "group") or "group").strip()

    finding_orders = item.get("finding_orders")

    if not isinstance(finding_orders, list):
        finding_orders = item.get("sample_finding_orders") or []

    sample_payloads = item.get("sample_payloads") or []
    sample_evidence = item.get("sample_evidence") or []

    if entry_type == "individual":
        finding_order = int(item.get("finding_order", 0) or 0)

        if not finding_orders and finding_order > 0:
            finding_orders = [finding_order]

        payload = item.get("payload")
        evidence = item.get("evidence")

        if not sample_payloads and payload:
            sample_payloads = [payload]

        if not sample_evidence and evidence:
            sample_evidence = [evidence]

        return {
            "entry_type": "individual",
            "parameter_probable": item.get("parameter_probable"),
            "context_probable": item.get("context_probable"),
            "severity_mode": item.get("severity") or item.get("severity_mode"),
            "payload_signature": item.get("payload_signature"),
            "occurrences": 1,
            "target_url": item.get("target_url"),
            "sample_finding_orders": finding_orders,
            "sample_payloads": sample_payloads,
            "sample_evidence": sample_evidence,
        }

    return {
        "entry_type": "group",
        "parameter_probable": item.get("parameter_probable"),
        "context_probable": item.get("context_probable"),
        "severity_mode": item.get("severity_mode"),
        "payload_signature": item.get("payload_signature"),
        "occurrences": int(item.get("occurrences", 1) or 1),
        "target_url": item.get("target_url"),
        "sample_finding_orders": finding_orders,
        "sample_payloads": sample_payloads,
        "sample_evidence": sample_evidence,
    }


# ==========================================================
# HELPERS PRIVADOS PARA HSECSCAN
# ==========================================================

def _unwrap_hsecscan_structured_payload(value: Any) -> Dict[str, Any]:
    """
    Acepta dos formas:
    1. El objeto interno devuelto por parse_hsecscan_output(...):
       { ok, response_info, observed_headers, missing_headers, summary, ... }

    2. El wrapper escrito en hsecscan.json:
       { target_url, tool_rc, parsed_at, structured: {...} }

    Devuelve siempre el objeto estructurado interno.
    """
    if not isinstance(value, dict):
        return {}

    structured = value.get("structured")

    if isinstance(structured, dict):
        return structured

    return value


def _extract_hsecscan_summary(structured_json: Any) -> Optional[Dict[str, Any]]:
    """
    Extrae summary desde el objeto estructurado de hsecscan.
    """
    structured = _unwrap_hsecscan_structured_payload(structured_json)
    summary = structured.get("summary")

    if isinstance(summary, dict):
        return summary

    return None


def _extract_hsecscan_checks(structured_json: Any) -> List[Dict[str, Any]]:
    """
    Extrae observed_headers + missing_headers desde el JSON estructurado.
    """
    structured = _unwrap_hsecscan_structured_payload(structured_json)

    observed = structured.get("observed_headers") or []
    missing = structured.get("missing_headers") or []

    result: List[Dict[str, Any]] = []

    if isinstance(observed, list):
        result.extend([item for item in observed if isinstance(item, dict)])

    if isinstance(missing, list):
        result.extend([item for item in missing if isinstance(item, dict)])

    return result


def _normalize_hsecscan_check_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Normaliza un registro de hsecscan para insertarlo en hsecscan_checks.
    """
    header_name = str(item.get("header_name") or "").strip()

    if not header_name:
        return None

    record_type = str(item.get("record_type") or "").strip().lower()

    if record_type not in ("observed", "missing"):
        record_type = "missing" if item.get("value") is None else "observed"

    risk_level = item.get("risk_level")

    if risk_level is not None:
        risk_level = str(risk_level).strip().lower()

    if risk_level not in ("alta", "media", "baja", "informativa"):
        risk_level = None

    return {
        "record_type": record_type,
        "display_status": item.get("display_status"),
        "header_name": header_name,
        "header_value": item.get("value"),
        "risk_level": risk_level,
        "reference_url": item.get("reference"),
        "security_description": item.get("security_description"),
        "security_reference": item.get("security_reference"),
        "recommendations": item.get("recommendations"),
        "cwe": item.get("cwe"),
        "cwe_url": item.get("cwe_url"),
        "https": item.get("https"),
        "raw_check_json": item,
    }
# ==========================================================
# HELPERS PRIVADOS PARA COMPARACIÓN CURL VS HSECSCAN
# ==========================================================

def _normalize_header_key(value: Any) -> str:
    """
    Normaliza nombres de cabeceras para comparar resultados entre herramientas.

    Ejemplo:
    Content-Security-Policy -> content-security-policy
    content_security_policy -> content-security-policy
    """
    text = str(value or "").strip().lower()
    text = text.replace("_", "-")

    while "--" in text:
        text = text.replace("--", "-")

    return text


def _display_header_name(value: Any) -> str:
    """
    Devuelve un nombre de cabecera amigable para mostrar en GUI.
    """
    text = str(value or "").strip()

    if not text:
        return "-"

    return text


def _curl_status_label(status: Any) -> str:
    """
    Convierte el status interno de http_tests a una etiqueta amigable.
    """
    value = str(status or "").strip().lower()

    if value == "passed":
        return "Aprobada"

    if value == "failed":
        return "Falló"

    if value == "warning":
        return "Advertencia"

    if value == "info":
        return "Informativo"

    return "No evaluada"


def _hsecscan_status_label(item: Optional[Dict[str, Any]]) -> str:
    """
    Convierte el registro de hsecscan a una etiqueta amigable.
    """
    if not item:
        return "No reportada"

    display_status = item.get("display_status")

    if display_status:
        return str(display_status)

    record_type = str(item.get("record_type") or "").strip().lower()

    if record_type == "missing":
        return "Faltante"

    if record_type == "observed":
        return "Observada"

    return "Reportada"


def _is_curl_weak(test: Optional[Dict[str, Any]]) -> bool:
    """
    Determina si curl detectó una debilidad.

    En el prototipo:
    - failed = debilidad clara
    - warning = advertencia relevante
    """
    if not test:
        return False

    status = str(test.get("status") or "").strip().lower()
    return status in ("failed", "warning")


def _is_hsecscan_weak(item: Optional[Dict[str, Any]]) -> bool:
    """
    Determina si hsecscan detectó una debilidad.

    hsecscan_checks guarda:
    - missing: cabecera faltante
    - observed: cabecera observada con advertencia o interés de seguridad
    """
    if not item:
        return False

    record_type = str(item.get("record_type") or "").strip().lower()
    return record_type in ("missing", "observed")


def _risk_rank(value: Any) -> int:
    """
    Rank numérico para ordenar riesgo.
    Menor número = mayor prioridad.
    """
    risk = str(value or "").strip().lower()

    if risk == "alta":
        return 1

    if risk == "media":
        return 2

    if risk == "baja":
        return 3

    if risk == "informativa":
        return 4

    return 5


def _infer_curl_risk_from_score(score_delta: Any) -> str:
    """
    Deriva una prioridad orientativa desde el score_delta de curl.

    Esto no cambia el scoring real; solo ayuda a ordenar la comparación.
    """
    try:
        score = int(score_delta or 0)
    except Exception:
        score = 0

    if score <= -20:
        return "alta"

    if score <= -10:
        return "media"

    if score < 0:
        return "baja"

    return "informativa"


def _merge_priority(curl_test: Optional[Dict[str, Any]], hsec_item: Optional[Dict[str, Any]]) -> str:
    """
    Define la prioridad visual de la fila comparada.

    Se toma el riesgo más alto entre:
    - riesgo inferido desde curl
    - risk_level de hsecscan
    """
    candidates: List[str] = []

    if curl_test and _is_curl_weak(curl_test):
        candidates.append(_infer_curl_risk_from_score(curl_test.get("score_delta")))

    if hsec_item and _is_hsecscan_weak(hsec_item):
        risk = hsec_item.get("risk_level")

        if risk:
            candidates.append(str(risk))

    if not candidates:
        return "informativa"

    return sorted(candidates, key=_risk_rank)[0]


def _comparison_result_label(
    curl_test: Optional[Dict[str, Any]],
    hsec_item: Optional[Dict[str, Any]],
) -> str:
    """
    Construye el resultado de comparación entre herramientas.
    """
    curl_weak = _is_curl_weak(curl_test)
    hsec_weak = _is_hsecscan_weak(hsec_item)

    if curl_weak and hsec_weak:
        return "Confirmado por curl y hsecscan"

    if curl_weak and not hsec_weak:
        return "Detectado por curl"

    if hsec_weak and not curl_weak:
        return "Detectado por hsecscan"

    if curl_test and not hsec_item:
        return "Sin contraste hsecscan"

    if hsec_item and not curl_test:
        return "No evaluado por curl"

    return "Sin debilidad confirmada"


def _build_curl_index(http_tests_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Crea índice de pruebas curl por cabecera.

    Usa header_name cuando existe.
    Si no existe, usa name/test_id como respaldo para no perder pruebas.
    """
    result: Dict[str, Dict[str, Any]] = {}

    for item in http_tests_rows:
        header_name = item.get("header_name") or item.get("name") or item.get("test_id")
        key = _normalize_header_key(header_name)

        if not key:
            continue

        current = result.get(key)

        if not current:
            result[key] = item
            continue

        current_is_weak = _is_curl_weak(current)
        incoming_is_weak = _is_curl_weak(item)

        if incoming_is_weak and not current_is_weak:
            result[key] = item
            continue

        current_risk = _risk_rank(_infer_curl_risk_from_score(current.get("score_delta")))
        incoming_risk = _risk_rank(_infer_curl_risk_from_score(item.get("score_delta")))

        if incoming_risk < current_risk:
            result[key] = item

    return result


def _build_hsecscan_index(hsecscan_checks_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Crea índice de hsecscan por cabecera.
    """
    result: Dict[str, Dict[str, Any]] = {}

    for item in hsecscan_checks_rows:
        key = _normalize_header_key(item.get("header_name"))

        if not key:
            continue

        current = result.get(key)

        if not current:
            result[key] = item
            continue

        current_rank = _risk_rank(current.get("risk_level"))
        incoming_rank = _risk_rank(item.get("risk_level"))

        if incoming_rank < current_rank:
            result[key] = item

    return result


def _build_header_layer_comparison(
    http_tests_rows: List[Dict[str, Any]],
    hsecscan_checks_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Construye la comparación curl vs hsecscan.

    Esta comparación se mantiene minimalista en GUI:
    - Cabecera
    - curl
    - hsecscan
    - Resultado
    - Prioridad
    """
    curl_index = _build_curl_index(http_tests_rows)
    hsecscan_index = _build_hsecscan_index(hsecscan_checks_rows)

    all_keys = sorted(set(curl_index.keys()) | set(hsecscan_index.keys()))

    rows: List[Dict[str, Any]] = []

    for key in all_keys:
        curl_test = curl_index.get(key)
        hsec_item = hsecscan_index.get(key)

        display_name = None

        if curl_test:
            display_name = curl_test.get("header_name") or curl_test.get("name") or curl_test.get("test_id")

        if not display_name and hsec_item:
            display_name = hsec_item.get("header_name")

        priority = _merge_priority(curl_test, hsec_item)

        rows.append(
            {
                "header_key": key,
                "header_name": _display_header_name(display_name),
                "priority": priority,
                "comparison_result": _comparison_result_label(curl_test, hsec_item),

                "curl_status_raw": curl_test.get("status") if curl_test else None,
                "curl_status": _curl_status_label(curl_test.get("status") if curl_test else None),
                "curl_score_delta": curl_test.get("score_delta") if curl_test else None,
                "curl_reason": curl_test.get("reason") if curl_test else None,
                "curl_recommendation": curl_test.get("recommendation") if curl_test else None,

                "hsecscan_record_type": hsec_item.get("record_type") if hsec_item else None,
                "hsecscan_status": _hsecscan_status_label(hsec_item),
                "hsecscan_risk_level": hsec_item.get("risk_level") if hsec_item else None,
                "hsecscan_description": hsec_item.get("security_description") if hsec_item else None,
                "hsecscan_recommendation": hsec_item.get("recommendations") if hsec_item else None,
                "hsecscan_cwe": hsec_item.get("cwe") if hsec_item else None,
            }
        )

    rows.sort(
        key=lambda item: (
            _risk_rank(item.get("priority")),
            0 if item.get("comparison_result") == "Confirmado por curl y hsecscan" else 1,
            str(item.get("header_name") or "").lower(),
        )
    )

    return rows


def _build_header_layer_comparison_summary(
    comparison_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construye un resumen para tarjetas de la GUI.
    """
    confirmed = 0
    only_curl = 0
    only_hsecscan = 0
    without_contrast = 0
    high_priority = 0

    for item in comparison_rows:
        result = item.get("comparison_result")

        if result == "Confirmado por curl y hsecscan":
            confirmed += 1
        elif result == "Detectado por curl":
            only_curl += 1
        elif result == "Detectado por hsecscan":
            only_hsecscan += 1
        elif result in ("Sin contraste hsecscan", "No evaluado por curl"):
            without_contrast += 1

        if item.get("priority") == "alta":
            high_priority += 1

    return {
        "total": len(comparison_rows),
        "confirmed": confirmed,
        "only_curl": only_curl,
        "only_hsecscan": only_hsecscan,
        "without_contrast": without_contrast,
        "high_priority": high_priority,
    }
# ==========================================================
# HELPERS PRIVADOS PARA RENDER XSS EN GUI
# ==========================================================

def _clean_display_text(value: Any) -> str:
    """
    Normaliza texto para decidir si un valor es útil para mostrar en GUI.

    Se usa para evitar que valores como None, "", "-" o "Unknown" sean tratados
    como hallazgos reales cuando no tienen payload ni evidencia.
    """
    text = str(value or "").strip()
    return " ".join(text.replace("\n", " ").replace("\r", " ").split())


def _is_empty_visual_value(value: Any) -> bool:
    """
    Determina si un valor debe considerarse vacío o no informativo.
    """
    text = _clean_display_text(value).lower()
    return text in ("", "-", "none", "null", "unknown", "desconocido")


def _as_list(value: Any) -> List[Any]:
    """
    Normaliza campos jsonb que deberían venir como lista.

    psycopg normalmente devuelve jsonb como list/dict, pero esta defensa permite
    tolerar casos donde el valor llegue como string JSON.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        raw = value.strip()

        if not raw:
            return []

        try:
            parsed = json.loads(raw)

            if isinstance(parsed, list):
                return parsed
        except Exception:
            return [value]

    return []


def _first_non_empty_text(values: Any) -> Optional[str]:
    """
    Devuelve el primer texto no vacío de una lista.
    """
    for item in _as_list(values):
        text = _clean_display_text(item)

        if text:
            return text

    return None


def _has_valid_xss_group_signal(group: Dict[str, Any]) -> bool:
    """
    Determina si un grupo XSS tiene suficiente señal para mostrarse.
    """
    severity = _clean_display_text(group.get("severity_mode")).lower()
    signature = _clean_display_text(group.get("payload_signature")).lower()
    parameter = _clean_display_text(group.get("parameter_probable")).lower()

    sample_payloads = _as_list(group.get("sample_payloads"))
    sample_evidence = _as_list(group.get("sample_evidence"))

    has_payload = any(not _is_empty_visual_value(item) for item in sample_payloads)
    has_evidence = any(not _is_empty_visual_value(item) for item in sample_evidence)

    severity_unknown = severity in ("", "-", "unknown", "desconocido")
    signature_unknown = signature in ("", "-", "unknown", "payload_desconocido")
    parameter_unknown = parameter in ("", "-", "unknown", "desconocido")

    if severity_unknown and signature_unknown and parameter_unknown and not has_payload and not has_evidence:
        return False

    return has_payload or has_evidence


def _has_valid_xss_finding_signal(finding: Dict[str, Any]) -> bool:
    """
    Determina si un hallazgo individual tiene suficiente señal para mostrarse.
    """
    payload = finding.get("payload")
    evidence = finding.get("evidence")
    severity = finding.get("severity")
    parameter = finding.get("param_name")

    has_payload = not _is_empty_visual_value(payload)
    has_evidence = not _is_empty_visual_value(evidence)

    severity_unknown = _clean_display_text(severity).lower() in ("", "-", "unknown", "desconocido")
    parameter_unknown = _clean_display_text(parameter).lower() in ("", "-", "unknown", "desconocido")

    if not has_payload and not has_evidence and severity_unknown and parameter_unknown:
        return False

    return has_payload or has_evidence


def _build_no_valid_xss_row(raw_count: int = 0) -> Dict[str, Any]:
    """
    Construye una fila informativa solo para el caso en que Dalfox haya producido
    registros no estructurados/vacíos, pero ningún hallazgo tenga payload/evidencia útil.

    Esta fila es un placeholder informativo y NO cuenta como hallazgo XSS real.
    """
    return {
        "row_order": "-",
        "parameter": "-",
        "payload": "-",
        "evidence": "Dalfox no devolvió payload/evidencia estructurada suficiente para mostrar un hallazgo XSS válido.",
        "severity": "Unknown",
        "occurrences": raw_count if raw_count > 0 else 1,
        "interpretation_humana": None,
        "risk_summary": None,
        "likely_root_cause": None,
        "recommended_review_area": None,
        "confidence": None,
        "model_name": None,
        "is_placeholder": True,
    }


# ==========================================================
# EJECUCIONES
# ==========================================================

def insert_execution(
    dsn: str,
    target_url: str,
    request_source: str = "cli",
    report_dir: Optional[str] = None,
    status: str = "initiated",
    scan_profile: str = "superficial",
    enable_hsecscan: bool = False,
    urls_ingresadas: int = 1,
    urls_evaluadas: int = 0,
) -> int:
    """
    Inserta una nueva ejecución y devuelve el id generado.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO executions (
                    target_url,
                    started_at,
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (
                    target_url,
                    utc_now(),
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                ),
            )
            row = cur.fetchone()

        conn.commit()

    if not row or "id" not in row:
        raise RuntimeError("No fue posible obtener el id de la ejecución insertada.")

    return int(row["id"])


def update_execution_status(
    dsn: str,
    execution_id: int,
    status: str,
    error_message: Optional[str] = None,
    urls_evaluadas: Optional[int] = None,
    finished: bool = False,
) -> None:
    """
    Actualiza el estado general de una ejecución.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            if urls_evaluadas is None:
                cur.execute(
                    """
                    UPDATE executions
                    SET status = %s,
                        error_message = %s,
                        finished_at = CASE WHEN %s THEN %s ELSE finished_at END
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        finished,
                        utc_now(),
                        execution_id,
                    ),
                )
            else:
                cur.execute(
                    """
                    UPDATE executions
                    SET status = %s,
                        error_message = %s,
                        urls_evaluadas = %s,
                        finished_at = CASE WHEN %s THEN %s ELSE finished_at END
                    WHERE id = %s;
                    """,
                    (
                        status,
                        error_message,
                        urls_evaluadas,
                        finished,
                        utc_now(),
                        execution_id,
                    ),
                )

        conn.commit()


def update_execution_running(dsn: str, execution_id: int) -> None:
    """
    Marca una ejecución como running.
    """
    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status="running",
        error_message=None,
        urls_evaluadas=0,
        finished=False,
    )


def update_execution_finished(
    dsn: str,
    execution_id: int,
    ok: bool,
    error_message: Optional[str] = None,
    urls_evaluadas: Optional[int] = None,
) -> None:
    """
    Marca la ejecución como finalizada o fallida.
    """
    new_status = "finished" if ok else "failed"

    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status=new_status,
        error_message=error_message,
        urls_evaluadas=urls_evaluadas,
        finished=True,
    )
# ==========================================================
# RESULTADOS HTTP: HEADERS + COOKIES + HTTP TESTS
# ==========================================================

def insert_header_results(
    dsn: str,
    execution_id: int,
    hdr_eval: Dict[str, Any],
    raw_headers_json: Dict[str, Any],
) -> None:
    """
    Inserta los resultados HTTP en forma normalizada.
    """
    _ = raw_headers_json

    header_details = _build_header_details_if_missing(hdr_eval)
    cookie_items = [_normalize_cookie_item(item) for item in (hdr_eval.get("cookies_flags", []) or [])]
    http_tests = [_normalize_http_test_item(item) for item in (hdr_eval.get("http_tests", []) or [])]

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO header_results (
                    execution_id,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    http_score,
                    http_grade
                )
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (
                    execution_id,
                    int(hdr_eval.get("headers_evaluadas", 0)),
                    int(hdr_eval.get("headers_presentes", 0)),
                    float(hdr_eval.get("cumplimiento_pct", 0)),
                    int(hdr_eval.get("http_score", 0)),
                    str(hdr_eval.get("http_grade", "F")),
                ),
            )

            for item in header_details:
                cur.execute(
                    """
                    INSERT INTO header_checks (
                        execution_id,
                        header_name,
                        is_present,
                        header_value
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (execution_id, header_name)
                    DO UPDATE SET
                        is_present = EXCLUDED.is_present,
                        header_value = EXCLUDED.header_value;
                    """,
                    (
                        execution_id,
                        str(item.get("header_name", "")),
                        bool(item.get("is_present")),
                        item.get("header_value"),
                    ),
                )

            for item in cookie_items:
                cur.execute(
                    """
                    INSERT INTO cookie_checks (
                        execution_id,
                        cookie_name,
                        cookie_raw,
                        secure,
                        httponly,
                        samesite_present,
                        samesite_value
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s);
                    """,
                    (
                        execution_id,
                        item.get("cookie_name"),
                        item.get("cookie_raw"),
                        item.get("secure"),
                        item.get("httponly"),
                        item.get("samesite_present"),
                        item.get("samesite_value"),
                    ),
                )

            for item in http_tests:
                if not item["test_id"] or not item["name"] or not item["category"] or not item["reason"] or not item["recommendation"]:
                    continue

                cur.execute(
                    """
                    INSERT INTO http_tests (
                        execution_id,
                        test_id,
                        name,
                        category,
                        status,
                        score_delta,
                        reason,
                        recommendation,
                        header_name,
                        header_value
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (execution_id, test_id)
                    DO UPDATE SET
                        name = EXCLUDED.name,
                        category = EXCLUDED.category,
                        status = EXCLUDED.status,
                        score_delta = EXCLUDED.score_delta,
                        reason = EXCLUDED.reason,
                        recommendation = EXCLUDED.recommendation,
                        header_name = EXCLUDED.header_name,
                        header_value = EXCLUDED.header_value;
                    """,
                    (
                        execution_id,
                        item["test_id"],
                        item["name"],
                        item["category"],
                        item["status"],
                        item["score_delta"],
                        item["reason"],
                        item["recommendation"],
                        item["header_name"],
                        item["header_value"],
                    ),
                )

        conn.commit()


# ==========================================================
# RESULTADOS CAPA 2: HSECSCAN
# ==========================================================

def insert_hsecscan_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    raw_output: str,
    structured_json: Optional[Dict[str, Any]] = None,
    summary_json: Optional[Dict[str, Any]] = None,
    hsecscan_checks: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Inserta o actualiza los resultados de la Capa 2 (hsecscan).
    """
    if summary_json is None and structured_json is not None:
        summary_json = _extract_hsecscan_summary(structured_json)

    if hsecscan_checks is None and structured_json is not None:
        hsecscan_checks = _extract_hsecscan_checks(structured_json)

    normalized_checks: List[Dict[str, Any]] = []

    for raw_item in hsecscan_checks or []:
        normalized = _normalize_hsecscan_check_item(raw_item)

        if normalized:
            normalized_checks.append(normalized)

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hsecscan_results (
                    execution_id,
                    tool_rc,
                    raw_output,
                    structured_json,
                    summary_json
                )
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)
                ON CONFLICT (execution_id)
                DO UPDATE SET
                    tool_rc = EXCLUDED.tool_rc,
                    raw_output = EXCLUDED.raw_output,
                    structured_json = EXCLUDED.structured_json,
                    summary_json = EXCLUDED.summary_json;
                """,
                (
                    execution_id,
                    int(tool_rc),
                    raw_output,
                    _json_or_none(structured_json),
                    _json_or_none(summary_json),
                ),
            )

            cur.execute(
                """
                DELETE FROM hsecscan_checks
                WHERE execution_id = %s;
                """,
                (execution_id,),
            )

            for item in normalized_checks:
                cur.execute(
                    """
                    INSERT INTO hsecscan_checks (
                        execution_id,
                        record_type,
                        display_status,
                        header_name,
                        header_value,
                        risk_level,
                        reference_url,
                        security_description,
                        security_reference,
                        recommendations,
                        cwe,
                        cwe_url,
                        https,
                        raw_check_json
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb
                    );
                    """,
                    (
                        execution_id,
                        item["record_type"],
                        item["display_status"],
                        item["header_name"],
                        item["header_value"],
                        item["risk_level"],
                        item["reference_url"],
                        item["security_description"],
                        item["security_reference"],
                        item["recommendations"],
                        item["cwe"],
                        item["cwe_url"],
                        item["https"],
                        _json_or_none(item["raw_check_json"]),
                    ),
                )

        conn.commit()


# ==========================================================
# RESULTADOS CAPA 3: DALFOX / XSS
# ==========================================================

def insert_xss_results(
    dsn: str,
    execution_id: int,
    tool_rc: int,
    findings_count: int,
    summary_json: Any,
    raw_output: str,
    xss_findings: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Inserta los resultados XSS en forma normalizada.
    """
    finding_rows = xss_findings or []

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO xss_results (
                    execution_id,
                    tool_rc,
                    findings_count,
                    summary_json,
                    raw_output
                )
                VALUES (%s, %s, %s, %s::jsonb, %s);
                """,
                (
                    execution_id,
                    int(tool_rc),
                    int(findings_count),
                    _json_or_none(summary_json),
                    raw_output,
                ),
            )

            for item in finding_rows:
                cur.execute(
                    """
                    INSERT INTO xss_findings (
                        execution_id,
                        finding_order,
                        source_type,
                        target_url,
                        param_name,
                        payload,
                        evidence,
                        severity,
                        raw_finding_json
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (execution_id, finding_order)
                    DO UPDATE SET
                        source_type = EXCLUDED.source_type,
                        target_url = EXCLUDED.target_url,
                        param_name = EXCLUDED.param_name,
                        payload = EXCLUDED.payload,
                        evidence = EXCLUDED.evidence,
                        severity = EXCLUDED.severity,
                        raw_finding_json = EXCLUDED.raw_finding_json;
                    """,
                    (
                        execution_id,
                        int(item.get("finding_order", 0)),
                        item.get("source_type"),
                        item.get("target_url"),
                        item.get("param_name"),
                        item.get("payload"),
                        item.get("evidence"),
                        item.get("severity"),
                        _json_or_none(item.get("raw_finding_json")),
                    ),
                )

        conn.commit()


# ==========================================================
# AGRUPACIÓN XSS PREPARADA PARA IA
# ==========================================================

def insert_xss_ai_groups(
    dsn: str,
    execution_id: int,
    xss_ai_payload: Dict[str, Any],
) -> None:
    """
    Persiste la agrupación XSS preparada para futura IA.
    """
    entries = xss_ai_payload.get("entries", []) or []

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for index, raw_item in enumerate(entries, start=1):
                item = _normalize_xss_ai_group_item(raw_item)

                cur.execute(
                    """
                    INSERT INTO xss_ai_groups (
                        execution_id,
                        group_order,
                        entry_type,
                        parameter_probable,
                        context_probable,
                        severity_mode,
                        payload_signature,
                        occurrences,
                        target_url,
                        sample_finding_orders,
                        sample_payloads,
                        sample_evidence
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                    ON CONFLICT (execution_id, group_order)
                    DO UPDATE SET
                        entry_type = EXCLUDED.entry_type,
                        parameter_probable = EXCLUDED.parameter_probable,
                        context_probable = EXCLUDED.context_probable,
                        severity_mode = EXCLUDED.severity_mode,
                        payload_signature = EXCLUDED.payload_signature,
                        occurrences = EXCLUDED.occurrences,
                        target_url = EXCLUDED.target_url,
                        sample_finding_orders = EXCLUDED.sample_finding_orders,
                        sample_payloads = EXCLUDED.sample_payloads,
                        sample_evidence = EXCLUDED.sample_evidence;
                    """,
                    (
                        execution_id,
                        index,
                        item["entry_type"],
                        item["parameter_probable"],
                        item["context_probable"],
                        item["severity_mode"],
                        item["payload_signature"],
                        item["occurrences"],
                        item["target_url"],
                        _json_or_none(item["sample_finding_orders"]),
                        _json_or_none(item["sample_payloads"]),
                        _json_or_none(item["sample_evidence"]),
                    ),
                )

        conn.commit()


def update_xss_ai_group_interpretations(
    dsn: str,
    execution_id: int,
    interpretations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza las interpretaciones generadas por IA sobre los grupos XSS.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in interpretations:
                group_order = int(item.get("group_order", 0) or 0)

                if group_order <= 0:
                    continue

                cur.execute(
                    """
                    UPDATE xss_ai_groups
                    SET interpretation_humana = %s,
                        risk_summary = %s,
                        likely_root_cause = %s,
                        recommended_review_area = %s,
                        confidence = %s,
                        model_name = %s
                    WHERE execution_id = %s
                      AND group_order = %s;
                    """,
                    (
                        item.get("interpretation_humana"),
                        item.get("risk_summary"),
                        item.get("likely_root_cause"),
                        item.get("recommended_review_area"),
                        item.get("confidence"),
                        model_name,
                        execution_id,
                        group_order,
                    ),
                )

        conn.commit()
# ==========================================================
# ARTIFACTS / EVIDENCIAS
# ==========================================================

def register_artifact(
    dsn: str,
    execution_id: int,
    artifact_type: str,
    file_name: str,
    relative_path: str,
    mime_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
) -> None:
    """
    Registra un artifact generado por una ejecución.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO artifacts (
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (execution_id, relative_path)
                DO UPDATE SET
                    artifact_type = EXCLUDED.artifact_type,
                    file_name = EXCLUDED.file_name,
                    mime_type = EXCLUDED.mime_type,
                    size_bytes = EXCLUDED.size_bytes;
                """,
                (
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes,
                ),
            )

        conn.commit()


def list_artifacts(dsn: str, execution_id: int) -> List[Dict[str, Any]]:
    """
    Devuelve la lista de artifacts de una ejecución.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes,
                    created_at
                FROM artifacts
                WHERE execution_id = %s
                ORDER BY created_at ASC, id ASC;
                """,
                (execution_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


# ==========================================================
# CONSULTAS DE HISTORIAL Y DETALLE
# ==========================================================

def list_execution_summaries(
    dsn: str,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    Lista ejecuciones desde la vista vw_execution_summary.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    target_url,
                    started_at,
                    finished_at,
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    http_score,
                    http_grade,
                    hsecscan_rc,
                    hsecscan_missing_headers_count,
                    hsecscan_observed_headers_count,
                    hsecscan_records_count,
                    dalfox_rc,
                    xss_findings_count,
                    hsecscan_checks_count,
                    xss_ai_groups_count,
                    artifacts_count
                FROM vw_execution_summary
                ORDER BY started_at DESC
                LIMIT %s OFFSET %s;
                """,
                (limit, offset),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


def get_execution_summary(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene una sola ejecución desde la vista de resumen.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    target_url,
                    started_at,
                    finished_at,
                    status,
                    request_source,
                    scan_profile,
                    enable_hsecscan,
                    urls_ingresadas,
                    urls_evaluadas,
                    report_dir,
                    headers_evaluadas,
                    headers_presentes,
                    cumplimiento_pct,
                    http_score,
                    http_grade,
                    hsecscan_rc,
                    hsecscan_missing_headers_count,
                    hsecscan_observed_headers_count,
                    hsecscan_records_count,
                    dalfox_rc,
                    xss_findings_count,
                    hsecscan_checks_count,
                    xss_ai_groups_count,
                    artifacts_count
                FROM vw_execution_summary
                WHERE id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()

        conn.commit()

    return dict(row) if row else None


def get_execution_detail(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Devuelve detalle enriquecido de una ejecución.

    También prepara:
    - xss_display_rows para la tabla XSS.
    - xss_display_count para que el conteo de la GUI coincida con la tabla.
    - header_layer_comparison para comparar curl vs hsecscan.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    e.id,
                    e.target_url,
                    e.started_at,
                    e.finished_at,
                    e.status,
                    e.error_message,
                    e.request_source,
                    e.scan_profile,
                    e.enable_hsecscan,
                    e.urls_ingresadas,
                    e.urls_evaluadas,
                    e.report_dir,

                    hr.headers_evaluadas,
                    hr.headers_presentes,
                    hr.cumplimiento_pct,
                    hr.http_score,
                    hr.http_grade,

                    hs.tool_rc AS hsecscan_rc,
                    hs.raw_output AS hsecscan_raw_output,
                    hs.structured_json AS hsecscan_structured_json,
                    hs.summary_json AS hsecscan_summary_json,

                    xr.tool_rc AS dalfox_rc,
                    xr.findings_count,
                    xr.summary_json,
                    xr.raw_output AS dalfox_raw_output
                FROM executions e
                LEFT JOIN header_results hr
                    ON hr.execution_id = e.id
                LEFT JOIN hsecscan_results hs
                    ON hs.execution_id = e.id
                LEFT JOIN xss_results xr
                    ON xr.execution_id = e.id
                WHERE e.id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()

            if not row:
                conn.commit()
                return None

            detail = dict(row)

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    header_name,
                    is_present,
                    header_value,
                    created_at
                FROM header_checks
                WHERE execution_id = %s
                ORDER BY id ASC;
                """,
                (execution_id,),
            )
            header_rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    cookie_name,
                    cookie_raw,
                    secure,
                    httponly,
                    samesite_present,
                    samesite_value,
                    created_at
                FROM cookie_checks
                WHERE execution_id = %s
                ORDER BY id ASC;
                """,
                (execution_id,),
            )
            cookie_rows_raw = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    test_id,
                    name,
                    category,
                    status,
                    score_delta,
                    reason,
                    recommendation,
                    header_name,
                    header_value,
                    created_at
                FROM http_tests
                WHERE execution_id = %s
                ORDER BY id ASC;
                """,
                (execution_id,),
            )
            http_tests_rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    record_type,
                    display_status,
                    header_name,
                    header_value,
                    risk_level,
                    reference_url,
                    security_description,
                    security_reference,
                    recommendations,
                    cwe,
                    cwe_url,
                    https,
                    raw_check_json,
                    created_at
                FROM hsecscan_checks
                WHERE execution_id = %s
                ORDER BY
                    CASE
                        WHEN risk_level = 'alta' THEN 1
                        WHEN risk_level = 'media' THEN 2
                        WHEN risk_level = 'baja' THEN 3
                        WHEN risk_level = 'informativa' THEN 4
                        ELSE 5
                    END,
                    record_type ASC,
                    header_name ASC,
                    id ASC;
                """,
                (execution_id,),
            )
            hsecscan_checks_rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    finding_order,
                    source_type,
                    target_url,
                    param_name,
                    payload,
                    evidence,
                    severity,
                    raw_finding_json,
                    created_at
                FROM xss_findings
                WHERE execution_id = %s
                ORDER BY finding_order ASC, id ASC;
                """,
                (execution_id,),
            )
            xss_findings_rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    group_order,
                    entry_type,
                    parameter_probable,
                    context_probable,
                    severity_mode,
                    payload_signature,
                    occurrences,
                    target_url,
                    sample_finding_orders,
                    sample_payloads,
                    sample_evidence,
                    interpretation_humana,
                    risk_summary,
                    likely_root_cause,
                    recommended_review_area,
                    confidence,
                    model_name,
                    created_at
                FROM xss_ai_groups
                WHERE execution_id = %s
                ORDER BY group_order ASC, id ASC;
                """,
                (execution_id,),
            )
            xss_ai_groups_rows = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    artifact_type,
                    file_name,
                    relative_path,
                    mime_type,
                    size_bytes,
                    created_at
                FROM artifacts
                WHERE execution_id = %s
                ORDER BY created_at ASC, id ASC;
                """,
                (execution_id,),
            )
            artifact_rows = [dict(r) for r in cur.fetchall()]

        conn.commit()

    # ------------------------------------------------------
    # Derivados de cabeceras
    # ------------------------------------------------------
    present_headers = [r["header_name"] for r in header_rows if r.get("is_present")]
    missing_headers = [r["header_name"] for r in header_rows if not r.get("is_present")]

    raw_headers_derived = {
        "headers": {
            str(r["header_name"]).lower(): r.get("header_value")
            for r in header_rows
            if r.get("is_present")
        }
    }

    # ------------------------------------------------------
    # Derivados de cookies para la GUI
    # ------------------------------------------------------
    cookies_flags_json: List[Dict[str, Any]] = []

    for row in cookie_rows_raw:
        cookies_flags_json.append(
            {
                "cookie": row.get("cookie_raw"),
                "secure": row.get("secure"),
                "httponly": row.get("httponly"),
                "samesite": row.get("samesite_present"),
                "cookie_name": row.get("cookie_name"),
                "cookie_raw": row.get("cookie_raw"),
                "samesite_present": row.get("samesite_present"),
                "samesite_value": row.get("samesite_value"),
            }
        )

    # ------------------------------------------------------
    # Derivados hsecscan para GUI
    # ------------------------------------------------------
    hsecscan_observed_checks = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "observed"
    ]

    hsecscan_missing_checks = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "missing"
    ]

    # ------------------------------------------------------
    # Comparación curl vs hsecscan
    # ------------------------------------------------------
    header_layer_comparison = _build_header_layer_comparison(
        http_tests_rows=http_tests_rows,
        hsecscan_checks_rows=hsecscan_checks_rows,
    )

    header_layer_comparison_summary = _build_header_layer_comparison_summary(
        header_layer_comparison
    )

    # ------------------------------------------------------
    # Enriquecer hallazgos individuales con IA cuando aplique
    # ------------------------------------------------------
    interpretation_by_finding_order: Dict[int, Dict[str, Any]] = {}

    for group in xss_ai_groups_rows:
        finding_orders = group.get("sample_finding_orders") or []

        if not isinstance(finding_orders, list):
            continue

        for raw_order in finding_orders:
            try:
                finding_order = int(raw_order)
            except Exception:
                continue

            interpretation_by_finding_order[finding_order] = {
                "interpretation_humana": group.get("interpretation_humana"),
                "risk_summary": group.get("risk_summary"),
                "likely_root_cause": group.get("likely_root_cause"),
                "recommended_review_area": group.get("recommended_review_area"),
                "confidence": group.get("confidence"),
                "model_name": group.get("model_name"),
            }

    enriched_xss_findings_rows: List[Dict[str, Any]] = []

    for row in xss_findings_rows:
        current = dict(row)
        finding_order = int(current.get("finding_order", 0) or 0)

        ai_data = interpretation_by_finding_order.get(finding_order, {})
        current["interpretation_humana"] = ai_data.get("interpretation_humana")
        current["risk_summary"] = ai_data.get("risk_summary")
        current["likely_root_cause"] = ai_data.get("likely_root_cause")
        current["recommended_review_area"] = ai_data.get("recommended_review_area")
        current["confidence"] = ai_data.get("confidence")
        current["model_name"] = ai_data.get("model_name")

        enriched_xss_findings_rows.append(current)

    # ------------------------------------------------------
    # Preparar filas de visualización XSS
    # ------------------------------------------------------
    valid_xss_ai_groups_rows = [
        group
        for group in xss_ai_groups_rows
        if _has_valid_xss_group_signal(group)
    ]

    valid_enriched_xss_findings_rows = [
        finding
        for finding in enriched_xss_findings_rows
        if _has_valid_xss_finding_signal(finding)
    ]

    has_real_groups = any(
        str(item.get("entry_type") or "").strip().lower() == "group"
        for item in valid_xss_ai_groups_rows
    )

    xss_display_mode = "grouped" if has_real_groups else "individual"
    xss_display_rows: List[Dict[str, Any]] = []

    if has_real_groups:
        for group in valid_xss_ai_groups_rows:
            sample_payloads = group.get("sample_payloads") or []
            sample_evidence = group.get("sample_evidence") or []

            payload_example = _first_non_empty_text(sample_payloads)
            evidence_example = _first_non_empty_text(sample_evidence)

            xss_display_rows.append(
                {
                    "row_order": group.get("group_order"),
                    "parameter": group.get("parameter_probable") or "-",
                    "payload": payload_example or "-",
                    "evidence": evidence_example or "-",
                    "severity": group.get("severity_mode") or "-",
                    "occurrences": group.get("occurrences") or 1,
                    "interpretation_humana": group.get("interpretation_humana"),
                    "risk_summary": group.get("risk_summary"),
                    "likely_root_cause": group.get("likely_root_cause"),
                    "recommended_review_area": group.get("recommended_review_area"),
                    "confidence": group.get("confidence"),
                    "model_name": group.get("model_name"),
                    "is_placeholder": False,
                }
            )

    else:
        for finding in valid_enriched_xss_findings_rows:
            xss_display_rows.append(
                {
                    "row_order": finding.get("finding_order"),
                    "parameter": finding.get("param_name") or "-",
                    "payload": finding.get("payload") or "-",
                    "evidence": finding.get("evidence") or "-",
                    "severity": finding.get("severity") or "-",
                    "occurrences": 1,
                    "interpretation_humana": finding.get("interpretation_humana"),
                    "risk_summary": finding.get("risk_summary"),
                    "likely_root_cause": finding.get("likely_root_cause"),
                    "recommended_review_area": finding.get("recommended_review_area"),
                    "confidence": finding.get("confidence"),
                    "model_name": finding.get("model_name"),
                    "is_placeholder": False,
                }
            )

    # Si no quedó ninguna fila válida, solo entonces se permite mostrar una fila
    # informativa. Esa fila no cuenta como hallazgo real.
    if not xss_display_rows and (xss_ai_groups_rows or enriched_xss_findings_rows):
        xss_display_rows.append(
            _build_no_valid_xss_row(
                raw_count=len(xss_ai_groups_rows) or len(enriched_xss_findings_rows)
            )
        )

    # Conteo real de hallazgos XSS que se muestran en la tabla.
    # No incluye placeholders informativos.
    xss_display_count = len(
        [
            row for row in xss_display_rows
            if not bool(row.get("is_placeholder"))
        ]
    )

    detail["present_json"] = present_headers
    detail["missing_json"] = missing_headers
    detail["raw_headers_json"] = raw_headers_derived

    detail["header_checks"] = header_rows
    detail["cookie_checks"] = cookie_rows_raw
    detail["cookies_flags_json"] = cookies_flags_json
    detail["http_tests"] = http_tests_rows

    detail["hsecscan_checks"] = hsecscan_checks_rows
    detail["hsecscan_observed_checks"] = hsecscan_observed_checks
    detail["hsecscan_missing_checks"] = hsecscan_missing_checks

    detail["header_layer_comparison"] = header_layer_comparison
    detail["header_layer_comparison_summary"] = header_layer_comparison_summary

    detail["xss_findings"] = enriched_xss_findings_rows
    detail["xss_ai_groups"] = xss_ai_groups_rows

    detail["xss_display_mode"] = xss_display_mode
    detail["xss_display_rows"] = xss_display_rows
    detail["xss_display_count"] = xss_display_count

    detail["artifacts"] = artifact_rows

    return detail