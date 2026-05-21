"""
db.py
- Acceso a PostgreSQL usando psycopg (psycopg3).
- Adaptado al esquema normalizado v10.

Responsabilidades:
- ejecutar operaciones CRUD de persistencia
- guardar resultados HTTP
- guardar cookies observadas y su interpretación
- guardar resultados hsecscan crudos y estructurados
- guardar checks normalizados de hsecscan
- guardar traducciones IA de hsecscan
- guardar resultados XSS
- guardar agrupación XSS preparada para IA
- guardar interpretaciones generadas por IA
- administrar el reporte general profesional editable
- administrar versiones históricas de solo lectura del reporte general
- registrar exportaciones PDF del reporte general
- exponer consultas de historial y detalle

Notas importantes:
- Este archivo no ejecuta herramientas externas.
- Este archivo no llama a IA directamente.
- El reporte general actual editable vive en professional_reports.
- Cada guardado del reporte general crea una fotografía histórica en
  professional_report_versions.
- Las versiones históricas no se editan; solo se consultan.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import config
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
# HELPERS PRIVADOS GENERALES
# ==========================================================

def _json_or_none(value: Any) -> Optional[str]:
    """
    Convierte un valor Python a texto JSON para insertarlo como json/jsonb.
    """
    if value is None:
        return None

    return json.dumps(value, ensure_ascii=False)


def _normalize_risk_level(value: Any) -> Optional[str]:
    """
    Normaliza un nivel de riesgo usado en varias tablas.
    """
    if value is None:
        return None

    text = str(value).strip().lower()

    if text in ("alta", "media", "baja", "informativa"):
        return text

    return None


def _clean_display_text(value: Any) -> str:
    """
    Normaliza texto para uso visual.
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
    Normaliza campos json/jsonb que deberían venir como lista.
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


# ==========================================================
# HELPERS PRIVADOS: HEADER / COOKIE / HTTP TESTS
# ==========================================================

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

    samesite_present = item.get("samesite_present")

    if samesite_present is None:
        samesite_present = bool(item.get("samesite"))

    return {
        "cookie_name": item.get("cookie_name"),
        "cookie_raw": str(cookie_raw or ""),
        "secure": bool(item.get("secure")),
        "httponly": bool(item.get("httponly")),
        "samesite_present": bool(samesite_present),
        "samesite_value": item.get("samesite_value"),
        "risk_level": _normalize_risk_level(item.get("risk_level")),
        "cwe_mappings": item.get("cwe_mappings"),
        "interpretation_humana": item.get("interpretation_humana"),
        "recommended_action": item.get("recommended_action"),
        "model_name": item.get("model_name"),
        "interpreted_at": item.get("interpreted_at"),
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


# ==========================================================
# HELPERS PRIVADOS: HSECSCAN
# ==========================================================

def _unwrap_hsecscan_structured_payload(value: Any) -> Dict[str, Any]:
    """
    Acepta el objeto interno del parser o el wrapper escrito en hsecscan.json.
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

    return {
        "record_type": record_type,
        "display_status": item.get("display_status"),
        "header_name": header_name,
        "header_value": item.get("value"),
        "risk_level": _normalize_risk_level(item.get("risk_level")),
        "reference_url": item.get("reference"),
        "security_description": item.get("security_description"),
        "security_reference": item.get("security_reference"),
        "recommendations": item.get("recommendations"),
        "cwe": item.get("cwe"),
        "cwe_url": item.get("cwe_url"),
        "https": item.get("https"),
        "security_description_es": item.get("security_description_es"),
        "recommendations_es": item.get("recommendations_es"),
        "cwe_es": item.get("cwe_es"),
        "translation_model_name": item.get("translation_model_name"),
        "translated_at": item.get("translated_at"),
        "raw_check_json": item,
    }


# ==========================================================
# HELPERS PRIVADOS: CLASIFICACIÓN CURL VS HSECSCAN
# ==========================================================

def _normalize_header_key(value: Any) -> str:
    """
    Normaliza nombres de cabeceras para comparar resultados entre herramientas.
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
    return text if text else "-"


def _config_text(name: str, fallback: str) -> str:
    """
    Lee un texto desde config.py con fallback.
    """
    value = getattr(config, name, fallback)
    text = str(value or "").strip()
    return text if text else fallback


def _config_dict(name: str) -> Dict[str, str]:
    """
    Lee un diccionario desde config.py con fallback.
    """
    value = getattr(config, name, {})

    if isinstance(value, dict):
        return value

    return {}


def _config_header_set(name: str, fallback: Optional[List[str]] = None) -> set[str]:
    """
    Lee una lista de cabeceras desde config.py y la normaliza como set.
    """
    raw_values = getattr(config, name, fallback or [])

    if not isinstance(raw_values, list):
        raw_values = fallback or []

    return {
        _normalize_header_key(item)
        for item in raw_values
        if _normalize_header_key(item)
    }


def _get_header_class_label(header_class: str) -> str:
    """
    Devuelve la etiqueta de clase de cabecera para GUI.
    """
    labels = _config_dict("HSECSCAN_HEADER_CLASS_LABELS")

    fallback_labels = {
        "principal": "Catálogo principal DASTXH",
        "complementaria_vigente": "Observación complementaria vigente",
        "historica_obsoleta": "Referencia histórica/obsoleta",
        "otra_observacion": "Otra observación hsecscan",
    }

    return str(labels.get(header_class) or fallback_labels.get(header_class) or header_class)


def _get_header_class_description(header_class: str) -> str:
    """
    Devuelve explicación de la clase de cabecera para GUI.
    """
    descriptions = _config_dict("HSECSCAN_HEADER_CLASS_DESCRIPTIONS")

    fallback_descriptions = {
        "principal": (
            "Cabecera incluida en el catálogo principal de DASTXH. "
            "hsecscan se usa como contraste para confirmar o ampliar la evidencia."
        ),
        "complementaria_vigente": (
            "Cabecera o elemento útil para contexto técnico, pero no forma parte "
            "del porcentaje principal de cumplimiento."
        ),
        "historica_obsoleta": (
            "Cabecera histórica, antigua, no recomendada como requisito principal "
            "o reemplazada por mecanismos modernos. Se conserva como referencia, "
            "pero no penaliza el cumplimiento principal."
        ),
        "otra_observacion": (
            "Registro reportado por hsecscan fuera del catálogo principal. "
            "Debe interpretarse como información complementaria."
        ),
    }

    return str(descriptions.get(header_class) or fallback_descriptions.get(header_class) or "")


def _classify_hsecscan_header(header_name: Any, raw_check_json: Any = None) -> Dict[str, str]:
    """
    Clasifica una cabecera de hsecscan sin depender de columnas nuevas.
    """
    raw_payload = raw_check_json if isinstance(raw_check_json, dict) else {}

    existing_class = str(raw_payload.get("header_class") or "").strip()

    primary_class = _config_text("HSECSCAN_HEADER_CLASS_PRIMARY", "principal")
    complementary_class = _config_text(
        "HSECSCAN_HEADER_CLASS_COMPLEMENTARY",
        "complementaria_vigente",
    )
    legacy_class = _config_text("HSECSCAN_HEADER_CLASS_LEGACY", "historica_obsoleta")
    other_class = _config_text("HSECSCAN_HEADER_CLASS_OTHER", "otra_observacion")

    valid_classes = {
        primary_class,
        complementary_class,
        legacy_class,
        other_class,
    }

    if existing_class in valid_classes:
        header_class = existing_class
    else:
        key = _normalize_header_key(header_name)

        primary_headers = _config_header_set(
            "HSECSCAN_PRIMARY_COMPARABLE_HEADERS",
            getattr(config, "REQUIRED_HEADERS", []),
        )

        complementary_headers = _config_header_set(
            "HSECSCAN_COMPLEMENTARY_CURRENT_HEADERS",
            [],
        )

        legacy_headers = _config_header_set(
            "HSECSCAN_LEGACY_OR_HISTORICAL_HEADERS",
            [],
        )

        if key in primary_headers:
            header_class = primary_class
        elif key in complementary_headers:
            header_class = complementary_class
        elif key in legacy_headers:
            header_class = legacy_class
        else:
            header_class = other_class

    return {
        "header_class": header_class,
        "header_class_label": raw_payload.get("header_class_label") or _get_header_class_label(header_class),
        "header_class_description": raw_payload.get("header_class_description") or _get_header_class_description(header_class),
    }


def _enrich_hsecscan_check_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Agrega clasificación DASTXH a una fila de hsecscan_checks.
    """
    item = dict(row)
    raw_check_json = item.get("raw_check_json")

    classification = _classify_hsecscan_header(
        header_name=item.get("header_name"),
        raw_check_json=raw_check_json,
    )

    item["header_class"] = classification.get("header_class")
    item["header_class_label"] = classification.get("header_class_label")
    item["header_class_description"] = classification.get("header_class_description")

    if _is_hsecscan_legacy(item):
        item["risk_level"] = "informativa"

    return item


def _enrich_hsecscan_check_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enriquece todas las filas hsecscan para GUI/comparación.
    """
    return [_enrich_hsecscan_check_row(row) for row in rows]


def _hsecscan_header_class(item: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Devuelve la clase DASTXH de un registro hsecscan.
    """
    if not item:
        return None

    header_class = item.get("header_class")

    if header_class:
        return str(header_class)

    classification = _classify_hsecscan_header(
        header_name=item.get("header_name"),
        raw_check_json=item.get("raw_check_json"),
    )

    return classification.get("header_class")


def _is_hsecscan_primary(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan está reportando una cabecera del catálogo principal.
    """
    return _hsecscan_header_class(item) == _config_text(
        "HSECSCAN_HEADER_CLASS_PRIMARY",
        "principal",
    )


def _is_hsecscan_complementary(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan está reportando una observación complementaria vigente.
    """
    return _hsecscan_header_class(item) == _config_text(
        "HSECSCAN_HEADER_CLASS_COMPLEMENTARY",
        "complementaria_vigente",
    )


def _is_hsecscan_legacy(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan está reportando una cabecera histórica/obsoleta.
    """
    return _hsecscan_header_class(item) == _config_text(
        "HSECSCAN_HEADER_CLASS_LEGACY",
        "historica_obsoleta",
    )


def _is_hsecscan_other_observation(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan está reportando otra observación fuera del catálogo principal.
    """
    return _hsecscan_header_class(item) == _config_text(
        "HSECSCAN_HEADER_CLASS_OTHER",
        "otra_observacion",
    )
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

    if _is_hsecscan_legacy(item):
        return "Referencia histórica"

    if _is_hsecscan_complementary(item):
        record_type = str(item.get("record_type") or "").strip().lower()

        if record_type == "missing":
            return "Complementaria faltante"

        if record_type == "observed":
            return "Complementaria observada"

        return "Complementaria"

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
    """
    if not test:
        return False

    status = str(test.get("status") or "").strip().lower()
    return status in ("failed", "warning")


def _is_hsecscan_weak(item: Optional[Dict[str, Any]]) -> bool:
    """
    Determina si hsecscan detectó una debilidad accionable comparable.
    """
    if not item:
        return False

    if not _is_hsecscan_primary(item):
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
    """
    if _is_hsecscan_legacy(hsec_item):
        return "informativa"

    if _is_hsecscan_complementary(hsec_item) or _is_hsecscan_other_observation(hsec_item):
        risk = hsec_item.get("risk_level") if hsec_item else None

        if risk:
            return str(risk)

        return "informativa"

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

    if _is_hsecscan_legacy(hsec_item):
        return "Referencia histórica/obsoleta hsecscan"

    if _is_hsecscan_complementary(hsec_item):
        if curl_weak:
            return "Detectado por curl; hsecscan aporta contexto"

        return "Observación complementaria hsecscan"

    if _is_hsecscan_other_observation(hsec_item):
        if curl_weak:
            return "Detectado por curl; hsecscan aporta observación"

        return "Otra observación hsecscan"

    if curl_weak and hsec_weak:
        return "Confirmado por curl y hsecscan"

    if curl_weak and not hsec_weak:
        if hsec_item:
            return "Detectado por curl"

        return "Sin contraste hsecscan"

    if hsec_weak and not curl_weak:
        if curl_test:
            return "Discrepancia: requiere revisión"

        return "Detectado por hsecscan"

    if curl_test and not hsec_item:
        return "Sin contraste hsecscan"

    if hsec_item and not curl_test:
        return "No evaluado por curl"

    return "Sin debilidad confirmada"


def _comparison_result_rank(value: Any) -> int:
    """
    Orden visual para comparación curl vs hsecscan.
    """
    text = str(value or "")

    if text == "Confirmado por curl y hsecscan":
        return 1

    if text == "Discrepancia: requiere revisión":
        return 2

    if text == "Detectado por curl":
        return 3

    if text == "Sin contraste hsecscan":
        return 4

    if text == "Detectado por hsecscan":
        return 5

    if text in (
        "Observación complementaria hsecscan",
        "Detectado por curl; hsecscan aporta contexto",
        "Otra observación hsecscan",
        "Detectado por curl; hsecscan aporta observación",
    ):
        return 6

    if text == "Referencia histórica/obsoleta hsecscan":
        return 7

    return 8


def _build_curl_index(http_tests_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Crea índice de pruebas curl por cabecera.
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

        if _is_curl_weak(item) and not _is_curl_weak(current):
            result[key] = item
            continue

        current_risk = _risk_rank(_infer_curl_risk_from_score(current.get("score_delta")))
        incoming_risk = _risk_rank(_infer_curl_risk_from_score(item.get("score_delta")))

        if incoming_risk < current_risk:
            result[key] = item

    return result


def _hsecscan_class_rank(item: Optional[Dict[str, Any]]) -> int:
    """
    Orden de prioridad para elegir un registro hsecscan si hay duplicados.
    """
    if _is_hsecscan_primary(item):
        return 1

    if _is_hsecscan_complementary(item):
        return 2

    if _is_hsecscan_other_observation(item):
        return 3

    if _is_hsecscan_legacy(item):
        return 4

    return 5


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

        current_class_rank = _hsecscan_class_rank(current)
        incoming_class_rank = _hsecscan_class_rank(item)

        if incoming_class_rank < current_class_rank:
            result[key] = item
            continue

        if incoming_class_rank == current_class_rank:
            if _risk_rank(item.get("risk_level")) < _risk_rank(current.get("risk_level")):
                result[key] = item

    return result


def _build_header_layer_comparison(
    http_tests_rows: List[Dict[str, Any]],
    hsecscan_checks_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Construye la comparación curl vs hsecscan.
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

        comparison_result = _comparison_result_label(curl_test, hsec_item)
        header_class = _hsecscan_header_class(hsec_item) if hsec_item else None

        rows.append(
            {
                "header_key": key,
                "header_name": _display_header_name(display_name),
                "priority": _merge_priority(curl_test, hsec_item),
                "comparison_result": comparison_result,
                "curl_status_raw": curl_test.get("status") if curl_test else None,
                "curl_status": _curl_status_label(curl_test.get("status") if curl_test else None),
                "curl_score_delta": curl_test.get("score_delta") if curl_test else None,
                "curl_reason": curl_test.get("reason") if curl_test else None,
                "curl_recommendation": curl_test.get("recommendation") if curl_test else None,
                "hsecscan_record_type": hsec_item.get("record_type") if hsec_item else None,
                "hsecscan_status": _hsecscan_status_label(hsec_item),
                "hsecscan_risk_level": hsec_item.get("risk_level") if hsec_item else None,
                "hsecscan_description": hsec_item.get("security_description") if hsec_item else None,
                "hsecscan_description_es": hsec_item.get("security_description_es") if hsec_item else None,
                "hsecscan_recommendation": hsec_item.get("recommendations") if hsec_item else None,
                "hsecscan_recommendation_es": hsec_item.get("recommendations_es") if hsec_item else None,
                "hsecscan_cwe": hsec_item.get("cwe") if hsec_item else None,
                "hsecscan_cwe_es": hsec_item.get("cwe_es") if hsec_item else None,
                "hsecscan_header_class": header_class,
                "hsecscan_header_class_label": hsec_item.get("header_class_label") if hsec_item else None,
                "hsecscan_header_class_description": hsec_item.get("header_class_description") if hsec_item else None,
            }
        )

    rows.sort(
        key=lambda item: (
            _risk_rank(item.get("priority")),
            _comparison_result_rank(item.get("comparison_result")),
            str(item.get("header_name") or "").lower(),
        )
    )

    return rows


def _build_header_layer_comparison_summary(comparison_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Construye un resumen para tarjetas de la GUI.
    """
    confirmed = 0
    only_curl = 0
    only_hsecscan = 0
    without_contrast = 0
    high_priority = 0
    discrepancies = 0
    complementary = 0
    legacy = 0
    other_observations = 0

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
        elif result == "Discrepancia: requiere revisión":
            discrepancies += 1
        elif result in (
            "Observación complementaria hsecscan",
            "Detectado por curl; hsecscan aporta contexto",
        ):
            complementary += 1
        elif result == "Referencia histórica/obsoleta hsecscan":
            legacy += 1
        elif result in (
            "Otra observación hsecscan",
            "Detectado por curl; hsecscan aporta observación",
        ):
            other_observations += 1

        if item.get("priority") == "alta":
            high_priority += 1

    return {
        "total": len(comparison_rows),
        "confirmed": confirmed,
        "only_curl": only_curl,
        "only_hsecscan": only_hsecscan,
        "without_contrast": without_contrast,
        "high_priority": high_priority,
        "discrepancies": discrepancies,
        "complementary": complementary,
        "legacy": legacy,
        "other_observations": other_observations,
    }


# ==========================================================
# HELPERS PRIVADOS: XSS DISPLAY
# ==========================================================

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
    Construye una fila informativa cuando no hay hallazgos XSS válidos.
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
# HELPERS PRIVADOS: REPORTE GENERAL PROFESIONAL
# ==========================================================

def _professional_report_editable_fields() -> List[str]:
    """
    Devuelve la lista de campos editables del reporte general.
    """
    fields = getattr(config, "PROFESSIONAL_REPORT_EDITABLE_FIELDS", [])

    if isinstance(fields, list) and fields:
        return [str(item) for item in fields]

    return [
        "report_title",
        "executive_summary",
        "scope_text",
        "methodology_text",
        "headers_analysis",
        "hsecscan_analysis",
        "cookies_analysis",
        "xss_analysis",
        "prioritized_findings",
        "general_recommendations",
        "limitations_text",
        "conclusion_text",
        "analyst_notes",
    ]


def _empty_professional_report_payload() -> Dict[str, Any]:
    """
    Crea el payload base del reporte profesional.
    """
    payload = {field: "" for field in _professional_report_editable_fields()}
    payload["report_title"] = getattr(
        config,
        "PROFESSIONAL_REPORT_DEFAULT_TITLE",
        "Reporte general DASTXH",
    )
    return payload


def _normalize_professional_report_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normaliza el contenido editable del reporte profesional.
    """
    normalized = _empty_professional_report_payload()

    if not isinstance(payload, dict):
        return normalized

    for field in _professional_report_editable_fields():
        value = payload.get(field)

        if value is None:
            value = ""

        normalized[field] = str(value)

    if not normalized.get("report_title", "").strip():
        normalized["report_title"] = getattr(
            config,
            "PROFESSIONAL_REPORT_DEFAULT_TITLE",
            "Reporte general DASTXH",
        )

    return normalized


def _professional_report_snapshot_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye snapshot_json desde una fila de professional_reports.
    """
    payload: Dict[str, Any] = {}

    for field in _professional_report_editable_fields():
        payload[field] = row.get(field) or ""

    return _normalize_professional_report_payload(payload)


def _professional_report_content_hash(snapshot: Dict[str, Any]) -> str:
    """
    Calcula un hash estable del snapshot para trazabilidad.
    """
    raw = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _professional_report_version_label(version_number: int) -> str:
    """
    Construye etiqueta amigable de versión.
    """
    prefix = getattr(config, "PROFESSIONAL_REPORT_VERSION_LABEL_PREFIX", "Versión")
    return f"{prefix} {version_number}"


def _next_professional_report_version_number(cur: Any, professional_report_id: int) -> int:
    """
    Calcula el siguiente número de versión para un reporte profesional.
    """
    cur.execute(
        """
        SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
        FROM professional_report_versions
        WHERE professional_report_id = %s;
        """,
        (professional_report_id,),
    )
    row = cur.fetchone()

    return int(row["next_version"] if row else 1)


def _insert_professional_report_version_cur(
    cur: Any,
    professional_report_id: int,
    execution_id: int,
    snapshot: Dict[str, Any],
    change_type: str,
    change_reason: Optional[str] = None,
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Inserta una versión histórica del reporte profesional.

    Esta función debe llamarse dentro de una transacción existente.
    """
    version_number = _next_professional_report_version_number(
        cur=cur,
        professional_report_id=professional_report_id,
    )
    content_hash = _professional_report_content_hash(snapshot)

    cur.execute(
        """
        INSERT INTO professional_report_versions (
            professional_report_id,
            execution_id,
            version_number,
            version_label,
            change_type,
            change_reason,
            snapshot_json,
            content_hash,
            created_at,
            created_by
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
        RETURNING
            id,
            professional_report_id,
            execution_id,
            version_number,
            version_label,
            change_type,
            change_reason,
            snapshot_json,
            content_hash,
            created_at,
            created_by;
        """,
        (
            professional_report_id,
            execution_id,
            version_number,
            _professional_report_version_label(version_number),
            change_type,
            change_reason,
            _json_or_none(snapshot),
            content_hash,
            utc_now(),
            created_by,
        ),
    )

    row = cur.fetchone()

    if not row:
        raise RuntimeError("No fue posible crear la versión histórica del reporte general.")

    return dict(row)


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
                    (status, error_message, finished, utc_now(), execution_id),
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
                    (status, error_message, urls_evaluadas, finished, utc_now(), execution_id),
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
    update_execution_status(
        dsn=dsn,
        execution_id=execution_id,
        status="finished" if ok else "failed",
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
                        samesite_value,
                        risk_level,
                        cwe_mappings,
                        interpretation_humana,
                        recommended_action,
                        model_name,
                        interpreted_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s::jsonb, %s, %s, %s, %s
                    );
                    """,
                    (
                        execution_id,
                        item.get("cookie_name"),
                        item.get("cookie_raw"),
                        item.get("secure"),
                        item.get("httponly"),
                        item.get("samesite_present"),
                        item.get("samesite_value"),
                        item.get("risk_level"),
                        _json_or_none(item.get("cwe_mappings")),
                        item.get("interpretation_humana"),
                        item.get("recommended_action"),
                        item.get("model_name"),
                        item.get("interpreted_at"),
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


def list_cookie_checks_for_interpretation(
    dsn: str,
    execution_id: int,
) -> List[Dict[str, Any]]:
    """
    Devuelve cookies observadas para análisis por reglas + IA.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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
                    risk_level,
                    cwe_mappings,
                    interpretation_humana,
                    recommended_action,
                    model_name,
                    interpreted_at,
                    created_at
                FROM cookie_checks
                WHERE execution_id = %s
                  AND (
                    interpretation_humana IS NULL
                    OR recommended_action IS NULL
                    OR risk_level IS NULL
                    OR cwe_mappings IS NULL
                  )
                ORDER BY id ASC;
                """,
                (execution_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


def update_cookie_check_interpretations(
    dsn: str,
    execution_id: int,
    interpretations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza cookies con interpretación por reglas + IA.
    """
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in interpretations:
                raw_cookie_id = item.get("cookie_check_id", item.get("check_id", item.get("id")))

                try:
                    cookie_check_id = int(raw_cookie_id)
                except Exception:
                    continue

                if cookie_check_id <= 0:
                    continue

                risk_level = _normalize_risk_level(item.get("risk_level"))

                cur.execute(
                    """
                    UPDATE cookie_checks
                    SET risk_level = %s,
                        cwe_mappings = %s::jsonb,
                        interpretation_humana = %s,
                        recommended_action = %s,
                        model_name = %s,
                        interpreted_at = %s
                    WHERE id = %s
                      AND execution_id = %s;
                    """,
                    (
                        risk_level,
                        _json_or_none(item.get("cwe_mappings")),
                        item.get("interpretation_humana"),
                        item.get("recommended_action"),
                        item.get("model_name") or model_name,
                        item.get("interpreted_at") or now,
                        cookie_check_id,
                        execution_id,
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
    Inserta o actualiza los resultados de hsecscan.
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
                        security_description_es,
                        recommendations_es,
                        cwe_es,
                        translation_model_name,
                        translated_at,
                        raw_check_json
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
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
                        item.get("security_description_es"),
                        item.get("recommendations_es"),
                        item.get("cwe_es"),
                        item.get("translation_model_name"),
                        item.get("translated_at"),
                        _json_or_none(item["raw_check_json"]),
                    ),
                )

        conn.commit()


def list_hsecscan_checks_for_translation(
    dsn: str,
    execution_id: int,
) -> List[Dict[str, Any]]:
    """
    Devuelve los checks de hsecscan que pueden enviarse al servicio de traducción IA.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
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
                    security_description,
                    recommendations,
                    cwe,
                    security_description_es,
                    recommendations_es,
                    cwe_es,
                    translation_model_name,
                    translated_at
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
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


def update_hsecscan_check_translations(
    dsn: str,
    execution_id: int,
    translations: List[Dict[str, Any]],
    model_name: Optional[str] = None,
) -> None:
    """
    Actualiza traducciones IA de hsecscan por id de hsecscan_checks.
    """
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            for item in translations:
                raw_check_id = item.get("check_id", item.get("id"))

                try:
                    check_id = int(raw_check_id)
                except Exception:
                    continue

                if check_id <= 0:
                    continue

                cur.execute(
                    """
                    UPDATE hsecscan_checks
                    SET security_description_es = %s,
                        recommendations_es = %s,
                        cwe_es = %s,
                        translation_model_name = %s,
                        translated_at = %s
                    WHERE id = %s
                      AND execution_id = %s;
                    """,
                    (
                        item.get("security_description_es"),
                        item.get("recommendations_es"),
                        item.get("cwe_es"),
                        item.get("translation_model_name") or model_name,
                        item.get("translated_at") or now,
                        check_id,
                        execution_id,
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


def insert_xss_ai_groups(
    dsn: str,
    execution_id: int,
    xss_ai_payload: Dict[str, Any],
) -> None:
    """
    Persiste la agrupación XSS preparada para IA.
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
# REPORTE GENERAL PROFESIONAL
# ==========================================================

def get_professional_report(
    dsn: str,
    execution_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene el reporte general profesional actual editable.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at
                FROM professional_reports
                WHERE execution_id = %s;
                """,
                (execution_id,),
            )
            row = cur.fetchone()

        conn.commit()

    return dict(row) if row else None


def get_or_create_professional_report(
    dsn: str,
    execution_id: int,
    initial_payload: Optional[Dict[str, Any]] = None,
    generated_by_ai: bool = False,
    ai_model_name: Optional[str] = None,
    change_type: str = "manual_save",
    change_reason: Optional[str] = None,
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Obtiene el reporte actual o crea uno nuevo.

    Si lo crea, también genera la versión histórica 1.
    """
    existing = get_professional_report(dsn, execution_id)

    if existing:
        return existing

    payload = _normalize_professional_report_payload(initial_payload)
    now = utc_now()

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO professional_reports (
                    execution_id,
                    current_version_number,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at
                )
                VALUES (
                    %s, 0, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                RETURNING
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at;
                """,
                (
                    execution_id,
                    getattr(config, "PROFESSIONAL_REPORT_STATUS_AI_GENERATED", "ai_generated")
                    if generated_by_ai
                    else getattr(config, "PROFESSIONAL_REPORT_STATUS_DRAFT", "draft"),
                    bool(generated_by_ai),
                    ai_model_name,
                    payload.get("report_title"),
                    payload.get("executive_summary"),
                    payload.get("scope_text"),
                    payload.get("methodology_text"),
                    payload.get("headers_analysis"),
                    payload.get("hsecscan_analysis"),
                    payload.get("cookies_analysis"),
                    payload.get("xss_analysis"),
                    payload.get("prioritized_findings"),
                    payload.get("general_recommendations"),
                    payload.get("limitations_text"),
                    payload.get("conclusion_text"),
                    payload.get("analyst_notes"),
                    now,
                    now,
                ),
            )
            report = dict(cur.fetchone())

            version = _insert_professional_report_version_cur(
                cur=cur,
                professional_report_id=int(report["id"]),
                execution_id=execution_id,
                snapshot=_professional_report_snapshot_from_row(report),
                change_type=change_type,
                change_reason=change_reason,
                created_by=created_by,
            )

            cur.execute(
                """
                UPDATE professional_reports
                SET current_version_number = %s,
                    current_version_id = %s,
                    updated_at = %s
                WHERE id = %s
                RETURNING
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at;
                """,
                (
                    version["version_number"],
                    version["id"],
                    utc_now(),
                    report["id"],
                ),
            )
            updated = dict(cur.fetchone())

        conn.commit()

    return updated
def save_professional_report(
    dsn: str,
    execution_id: int,
    payload: Dict[str, Any],
    generated_by_ai: bool = False,
    ai_model_name: Optional[str] = None,
    change_type: str = "manual_save",
    change_reason: Optional[str] = None,
    updated_by: str = "web",
) -> Dict[str, Any]:
    """
    Guarda el reporte general editable y crea una nueva versión histórica.
    """
    normalized = _normalize_professional_report_payload(payload)
    existing = get_professional_report(dsn, execution_id)

    if not existing:
        return get_or_create_professional_report(
            dsn=dsn,
            execution_id=execution_id,
            initial_payload=normalized,
            generated_by_ai=generated_by_ai,
            ai_model_name=ai_model_name,
            change_type=change_type,
            change_reason=change_reason,
            created_by=updated_by,
        )

    report_id = int(existing["id"])
    now = utc_now()

    status = (
        getattr(config, "PROFESSIONAL_REPORT_STATUS_AI_GENERATED", "ai_generated")
        if generated_by_ai
        else getattr(config, "PROFESSIONAL_REPORT_STATUS_EDITED", "edited")
    )

    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE professional_reports
                SET status = %s,
                    generated_by_ai = CASE WHEN %s THEN TRUE ELSE generated_by_ai END,
                    ai_model_name = COALESCE(%s, ai_model_name),
                    report_title = %s,
                    executive_summary = %s,
                    scope_text = %s,
                    methodology_text = %s,
                    headers_analysis = %s,
                    hsecscan_analysis = %s,
                    cookies_analysis = %s,
                    xss_analysis = %s,
                    prioritized_findings = %s,
                    general_recommendations = %s,
                    limitations_text = %s,
                    conclusion_text = %s,
                    analyst_notes = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s
                RETURNING
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at;
                """,
                (
                    status,
                    bool(generated_by_ai),
                    ai_model_name,
                    normalized.get("report_title"),
                    normalized.get("executive_summary"),
                    normalized.get("scope_text"),
                    normalized.get("methodology_text"),
                    normalized.get("headers_analysis"),
                    normalized.get("hsecscan_analysis"),
                    normalized.get("cookies_analysis"),
                    normalized.get("xss_analysis"),
                    normalized.get("prioritized_findings"),
                    normalized.get("general_recommendations"),
                    normalized.get("limitations_text"),
                    normalized.get("conclusion_text"),
                    normalized.get("analyst_notes"),
                    now,
                    report_id,
                    execution_id,
                ),
            )
            updated_report = dict(cur.fetchone())

            version = _insert_professional_report_version_cur(
                cur=cur,
                professional_report_id=report_id,
                execution_id=execution_id,
                snapshot=_professional_report_snapshot_from_row(updated_report),
                change_type=change_type,
                change_reason=change_reason,
                created_by=updated_by,
            )

            cur.execute(
                """
                UPDATE professional_reports
                SET current_version_number = %s,
                    current_version_id = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s
                RETURNING
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at;
                """,
                (
                    version["version_number"],
                    version["id"],
                    utc_now(),
                    report_id,
                    execution_id,
                ),
            )
            final_report = dict(cur.fetchone())

        conn.commit()

    final_report["created_version"] = version
    return final_report


def create_professional_report_pdf_snapshot_version(
    dsn: str,
    execution_id: int,
    payload: Dict[str, Any],
    change_reason: Optional[str] = "Snapshot usado para exportación PDF.",
    created_by: str = "web",
) -> Dict[str, Any]:
    """
    Crea una versión histórica específica para exportación PDF.
    """
    report = save_professional_report(
        dsn=dsn,
        execution_id=execution_id,
        payload=payload,
        generated_by_ai=False,
        ai_model_name=None,
        change_type=getattr(
            config,
            "PROFESSIONAL_REPORT_CHANGE_TYPE_PDF_EXPORT_SNAPSHOT",
            "pdf_export_snapshot",
        ),
        change_reason=change_reason,
        updated_by=created_by,
    )

    version = report.get("created_version")

    if not isinstance(version, dict):
        raise RuntimeError("No fue posible crear la versión de snapshot para PDF.")

    return version


def list_professional_report_versions(
    dsn: str,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Lista versiones históricas de un reporte general.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    professional_report_id,
                    execution_id,
                    version_number,
                    version_label,
                    change_type,
                    change_reason,
                    snapshot_json,
                    content_hash,
                    created_at,
                    created_by
                FROM professional_report_versions
                WHERE professional_report_id = %s
                ORDER BY version_number DESC;
                """,
                (professional_report_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


def get_professional_report_version(
    dsn: str,
    version_id: int,
) -> Optional[Dict[str, Any]]:
    """
    Obtiene una versión histórica específica.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    professional_report_id,
                    execution_id,
                    version_number,
                    version_label,
                    change_type,
                    change_reason,
                    snapshot_json,
                    content_hash,
                    created_at,
                    created_by
                FROM professional_report_versions
                WHERE id = %s;
                """,
                (version_id,),
            )
            row = cur.fetchone()

        conn.commit()

    return dict(row) if row else None


def register_professional_report_pdf_export(
    dsn: str,
    professional_report_id: int,
    professional_report_version_id: int,
    execution_id: int,
    artifact_id: Optional[int],
    pdf_file_name: str,
    pdf_relative_path: str,
    exported_by: str = "web",
) -> Dict[str, Any]:
    """
    Registra una exportación PDF del reporte general profesional.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO professional_report_pdf_exports (
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    exported_at,
                    exported_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING
                    id,
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    exported_at,
                    exported_by;
                """,
                (
                    professional_report_id,
                    professional_report_version_id,
                    execution_id,
                    artifact_id,
                    pdf_file_name,
                    pdf_relative_path,
                    utc_now(),
                    exported_by,
                ),
            )
            export_row = dict(cur.fetchone())

            cur.execute(
                """
                UPDATE professional_reports
                SET status = %s,
                    updated_at = %s
                WHERE id = %s
                  AND execution_id = %s;
                """,
                (
                    getattr(config, "PROFESSIONAL_REPORT_STATUS_PDF_EXPORTED", "pdf_exported"),
                    utc_now(),
                    professional_report_id,
                    execution_id,
                ),
            )

        conn.commit()

    return export_row


def list_professional_report_pdf_exports(
    dsn: str,
    professional_report_id: int,
) -> List[Dict[str, Any]]:
    """
    Lista exportaciones PDF de un reporte general.
    """
    with connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    prpdf.id,
                    prpdf.professional_report_id,
                    prpdf.professional_report_version_id,
                    prpdf.execution_id,
                    prpdf.artifact_id,
                    prpdf.pdf_file_name,
                    prpdf.pdf_relative_path,
                    prpdf.exported_at,
                    prpdf.exported_by,
                    prv.version_number,
                    prv.version_label,
                    a.file_name AS artifact_file_name,
                    a.relative_path AS artifact_relative_path,
                    a.mime_type AS artifact_mime_type,
                    a.size_bytes AS artifact_size_bytes
                FROM professional_report_pdf_exports prpdf
                LEFT JOIN professional_report_versions prv
                    ON prv.id = prpdf.professional_report_version_id
                LEFT JOIN artifacts a
                    ON a.id = prpdf.artifact_id
                WHERE prpdf.professional_report_id = %s
                ORDER BY prpdf.exported_at DESC, prpdf.id DESC;
                """,
                (professional_report_id,),
            )
            rows = cur.fetchall()

        conn.commit()

    return [dict(r) for r in rows]


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
) -> int:
    """
    Registra un artifact generado por una ejecución y devuelve su id.

    Compatibilidad:
    - Antes esta función no devolvía valor.
    - Los llamadores existentes pueden ignorar el retorno sin problema.
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
                    size_bytes = EXCLUDED.size_bytes
                RETURNING id;
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
            row = cur.fetchone()

        conn.commit()

    return int(row["id"]) if row and row.get("id") is not None else 0


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
                    cookie_checks_count,
                    cookie_interpreted_checks_count,
                    hsecscan_checks_count,
                    hsecscan_translated_checks_count,
                    xss_ai_groups_count,
                    artifacts_count,
                    professional_report_id,
                    professional_report_current_version,
                    professional_report_status,
                    professional_report_updated_at,
                    professional_report_versions_count,
                    professional_report_pdf_exports_count
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
                SELECT *
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
                SELECT id, execution_id, header_name, is_present, header_value, created_at
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
                    risk_level,
                    cwe_mappings,
                    interpretation_humana,
                    recommended_action,
                    model_name,
                    interpreted_at,
                    created_at
                FROM cookie_checks
                WHERE execution_id = %s
                ORDER BY
                    CASE
                        WHEN risk_level = 'alta' THEN 1
                        WHEN risk_level = 'media' THEN 2
                        WHEN risk_level = 'baja' THEN 3
                        WHEN risk_level = 'informativa' THEN 4
                        ELSE 5
                    END,
                    id ASC;
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
                    security_description_es,
                    recommendations_es,
                    cwe_es,
                    translation_model_name,
                    translated_at,
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

            cur.execute(
                """
                SELECT
                    id,
                    execution_id,
                    current_version_number,
                    current_version_id,
                    status,
                    generated_by_ai,
                    ai_model_name,
                    report_title,
                    executive_summary,
                    scope_text,
                    methodology_text,
                    headers_analysis,
                    hsecscan_analysis,
                    cookies_analysis,
                    xss_analysis,
                    prioritized_findings,
                    general_recommendations,
                    limitations_text,
                    conclusion_text,
                    analyst_notes,
                    created_at,
                    updated_at
                FROM professional_reports
                WHERE execution_id = %s;
                """,
                (execution_id,),
            )
            professional_report_row = cur.fetchone()
            professional_report = dict(professional_report_row) if professional_report_row else None

            professional_report_versions: List[Dict[str, Any]] = []
            professional_report_pdf_exports: List[Dict[str, Any]] = []

            if professional_report:
                cur.execute(
                    """
                    SELECT
                        id,
                        professional_report_id,
                        execution_id,
                        version_number,
                        version_label,
                        change_type,
                        change_reason,
                        snapshot_json,
                        content_hash,
                        created_at,
                        created_by
                    FROM professional_report_versions
                    WHERE professional_report_id = %s
                    ORDER BY version_number DESC;
                    """,
                    (professional_report["id"],),
                )
                professional_report_versions = [dict(r) for r in cur.fetchall()]

                cur.execute(
                    """
                    SELECT
                        prpdf.id,
                        prpdf.professional_report_id,
                        prpdf.professional_report_version_id,
                        prpdf.execution_id,
                        prpdf.artifact_id,
                        prpdf.pdf_file_name,
                        prpdf.pdf_relative_path,
                        prpdf.exported_at,
                        prpdf.exported_by,
                        prv.version_number,
                        prv.version_label,
                        a.file_name AS artifact_file_name,
                        a.relative_path AS artifact_relative_path,
                        a.mime_type AS artifact_mime_type,
                        a.size_bytes AS artifact_size_bytes
                    FROM professional_report_pdf_exports prpdf
                    LEFT JOIN professional_report_versions prv
                        ON prv.id = prpdf.professional_report_version_id
                    LEFT JOIN artifacts a
                        ON a.id = prpdf.artifact_id
                    WHERE prpdf.professional_report_id = %s
                    ORDER BY prpdf.exported_at DESC, prpdf.id DESC;
                    """,
                    (professional_report["id"],),
                )
                professional_report_pdf_exports = [dict(r) for r in cur.fetchall()]

        conn.commit()

    present_headers = [r["header_name"] for r in header_rows if r.get("is_present")]
    missing_headers = [r["header_name"] for r in header_rows if not r.get("is_present")]

    raw_headers_derived = {
        "headers": {
            str(r["header_name"]).lower(): r.get("header_value")
            for r in header_rows
            if r.get("is_present")
        }
    }

    cookies_flags_json: List[Dict[str, Any]] = []

    for row_item in cookie_rows_raw:
        cookies_flags_json.append(
            {
                "id": row_item.get("id"),
                "cookie": row_item.get("cookie_raw"),
                "secure": row_item.get("secure"),
                "httponly": row_item.get("httponly"),
                "samesite": row_item.get("samesite_present"),
                "cookie_name": row_item.get("cookie_name"),
                "cookie_raw": row_item.get("cookie_raw"),
                "samesite_present": row_item.get("samesite_present"),
                "samesite_value": row_item.get("samesite_value"),
                "risk_level": row_item.get("risk_level"),
                "cwe_mappings": row_item.get("cwe_mappings"),
                "interpretation_humana": row_item.get("interpretation_humana"),
                "recommended_action": row_item.get("recommended_action"),
                "model_name": row_item.get("model_name"),
                "interpreted_at": row_item.get("interpreted_at"),
            }
        )

    hsecscan_checks_rows = _enrich_hsecscan_check_rows(hsecscan_checks_rows)

    hsecscan_observed_checks = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "observed"
    ]

    hsecscan_missing_checks = [
        item for item in hsecscan_checks_rows
        if str(item.get("record_type") or "").lower() == "missing"
    ]

    hsecscan_primary_checks = [
        item for item in hsecscan_checks_rows
        if _is_hsecscan_primary(item)
    ]

    hsecscan_complementary_checks = [
        item for item in hsecscan_checks_rows
        if _is_hsecscan_complementary(item)
    ]

    hsecscan_legacy_checks = [
        item for item in hsecscan_checks_rows
        if _is_hsecscan_legacy(item)
    ]

    hsecscan_other_observation_checks = [
        item for item in hsecscan_checks_rows
        if _is_hsecscan_other_observation(item)
    ]

    hsecscan_class_summary = {
        "primary": len(hsecscan_primary_checks),
        "complementary": len(hsecscan_complementary_checks),
        "legacy": len(hsecscan_legacy_checks),
        "other_observations": len(hsecscan_other_observation_checks),
    }

    header_layer_comparison = _build_header_layer_comparison(
        http_tests_rows=http_tests_rows,
        hsecscan_checks_rows=hsecscan_checks_rows,
    )

    header_layer_comparison_summary = _build_header_layer_comparison_summary(
        header_layer_comparison
    )

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

    for finding in xss_findings_rows:
        current = dict(finding)
        finding_order = int(current.get("finding_order", 0) or 0)
        ai_data = interpretation_by_finding_order.get(finding_order, {})
        current["interpretation_humana"] = ai_data.get("interpretation_humana")
        current["risk_summary"] = ai_data.get("risk_summary")
        current["likely_root_cause"] = ai_data.get("likely_root_cause")
        current["recommended_review_area"] = ai_data.get("recommended_review_area")
        current["confidence"] = ai_data.get("confidence")
        current["model_name"] = ai_data.get("model_name")
        enriched_xss_findings_rows.append(current)

    valid_xss_ai_groups_rows = [
        group for group in xss_ai_groups_rows
        if _has_valid_xss_group_signal(group)
    ]

    valid_enriched_xss_findings_rows = [
        finding for finding in enriched_xss_findings_rows
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

    if not xss_display_rows and (xss_ai_groups_rows or enriched_xss_findings_rows):
        xss_display_rows.append(
            _build_no_valid_xss_row(
                raw_count=len(xss_ai_groups_rows) or len(enriched_xss_findings_rows)
            )
        )

    xss_display_count = len(
        [item for item in xss_display_rows if not bool(item.get("is_placeholder"))]
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
    detail["hsecscan_primary_checks"] = hsecscan_primary_checks
    detail["hsecscan_complementary_checks"] = hsecscan_complementary_checks
    detail["hsecscan_legacy_checks"] = hsecscan_legacy_checks
    detail["hsecscan_other_observation_checks"] = hsecscan_other_observation_checks
    detail["hsecscan_class_summary"] = hsecscan_class_summary
    detail["header_layer_comparison"] = header_layer_comparison
    detail["header_layer_comparison_summary"] = header_layer_comparison_summary
    detail["xss_findings"] = enriched_xss_findings_rows
    detail["xss_ai_groups"] = xss_ai_groups_rows
    detail["xss_display_mode"] = xss_display_mode
    detail["xss_display_rows"] = xss_display_rows
    detail["xss_display_count"] = xss_display_count
    detail["artifacts"] = artifact_rows
    detail["professional_report"] = professional_report
    detail["professional_report_versions"] = professional_report_versions
    detail["professional_report_pdf_exports"] = professional_report_pdf_exports

    return detail