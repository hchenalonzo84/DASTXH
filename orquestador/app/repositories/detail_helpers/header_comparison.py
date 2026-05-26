"""
header_comparison.py
- Comparación entre verificación principal curl y hsecscan.

Responsabilidad:
- Construir filas comparativas curl vs hsecscan.
- Generar resumen de comparación para tarjetas de GUI.
- Calcular prioridad visual de hallazgos.

Nota:
- Este archivo no consulta base de datos.
- Recibe filas ya consultadas desde detail_queries.py.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from repositories.detail_helpers.hsecscan_classification import (
    display_header_name,
    hsecscan_header_class,
    is_hsecscan_complementary,
    is_hsecscan_legacy,
    is_hsecscan_other_observation,
    is_hsecscan_primary,
    normalize_header_key,
)


def curl_status_label(status: Any) -> str:
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


def hsecscan_status_label(item: Optional[Dict[str, Any]]) -> str:
    """
    Convierte el registro de hsecscan a una etiqueta amigable.
    """
    if not item:
        return "No reportada"

    if is_hsecscan_legacy(item):
        return "Referencia histórica"

    if is_hsecscan_complementary(item):
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


def is_curl_weak(test: Optional[Dict[str, Any]]) -> bool:
    """
    Determina si curl detectó una debilidad.
    """
    if not test:
        return False

    status = str(test.get("status") or "").strip().lower()
    return status in ("failed", "warning")


def is_hsecscan_weak(item: Optional[Dict[str, Any]]) -> bool:
    """
    Determina si hsecscan detectó una debilidad accionable comparable.
    """
    if not item:
        return False

    if not is_hsecscan_primary(item):
        return False

    record_type = str(item.get("record_type") or "").strip().lower()
    return record_type in ("missing", "observed")


def risk_rank(value: Any) -> int:
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


def infer_curl_risk_from_score(score_delta: Any) -> str:
    """
    Deriva una prioridad orientativa desde score_delta de curl.
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


def merge_priority(
    curl_test: Optional[Dict[str, Any]],
    hsec_item: Optional[Dict[str, Any]],
) -> str:
    """
    Define la prioridad visual de una fila comparada.
    """
    if is_hsecscan_legacy(hsec_item):
        return "informativa"

    if is_hsecscan_complementary(hsec_item) or is_hsecscan_other_observation(hsec_item):
        risk = hsec_item.get("risk_level") if hsec_item else None

        if risk:
            return str(risk)

        return "informativa"

    candidates: List[str] = []

    if curl_test and is_curl_weak(curl_test):
        candidates.append(infer_curl_risk_from_score(curl_test.get("score_delta")))

    if hsec_item and is_hsecscan_weak(hsec_item):
        risk = hsec_item.get("risk_level")

        if risk:
            candidates.append(str(risk))

    if not candidates:
        return "informativa"

    return sorted(candidates, key=risk_rank)[0]


def comparison_result_label(
    curl_test: Optional[Dict[str, Any]],
    hsec_item: Optional[Dict[str, Any]],
) -> str:
    """
    Construye el resultado textual de comparación entre herramientas.
    """
    curl_weak = is_curl_weak(curl_test)
    hsec_weak = is_hsecscan_weak(hsec_item)

    if is_hsecscan_legacy(hsec_item):
        return "Referencia histórica/obsoleta hsecscan"

    if is_hsecscan_complementary(hsec_item):
        if curl_weak:
            return "Detectado por curl; hsecscan aporta contexto"

        return "Observación complementaria hsecscan"

    if is_hsecscan_other_observation(hsec_item):
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


def comparison_result_rank(value: Any) -> int:
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


def build_curl_index(http_tests_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Crea índice de pruebas curl por cabecera.
    """
    result: Dict[str, Dict[str, Any]] = {}

    for item in http_tests_rows:
        header_name = item.get("header_name") or item.get("name") or item.get("test_id")
        key = normalize_header_key(header_name)

        if not key:
            continue

        current = result.get(key)

        if not current:
            result[key] = item
            continue

        if is_curl_weak(item) and not is_curl_weak(current):
            result[key] = item
            continue

        current_risk = risk_rank(infer_curl_risk_from_score(current.get("score_delta")))
        incoming_risk = risk_rank(infer_curl_risk_from_score(item.get("score_delta")))

        if incoming_risk < current_risk:
            result[key] = item

    return result


def hsecscan_class_rank(item: Optional[Dict[str, Any]]) -> int:
    """
    Prioridad para elegir un registro hsecscan si hay duplicados.
    """
    if is_hsecscan_primary(item):
        return 1

    if is_hsecscan_complementary(item):
        return 2

    if is_hsecscan_other_observation(item):
        return 3

    if is_hsecscan_legacy(item):
        return 4

    return 5


def build_hsecscan_index(
    hsecscan_checks_rows: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Crea índice de hsecscan por cabecera.
    """
    result: Dict[str, Dict[str, Any]] = {}

    for item in hsecscan_checks_rows:
        key = normalize_header_key(item.get("header_name"))

        if not key:
            continue

        current = result.get(key)

        if not current:
            result[key] = item
            continue

        current_class_rank = hsecscan_class_rank(current)
        incoming_class_rank = hsecscan_class_rank(item)

        if incoming_class_rank < current_class_rank:
            result[key] = item
            continue

        if incoming_class_rank == current_class_rank:
            if risk_rank(item.get("risk_level")) < risk_rank(current.get("risk_level")):
                result[key] = item

    return result


def build_header_layer_comparison(
    http_tests_rows: List[Dict[str, Any]],
    hsecscan_checks_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Construye la comparación curl vs hsecscan.
    """
    curl_index = build_curl_index(http_tests_rows)
    hsecscan_index = build_hsecscan_index(hsecscan_checks_rows)
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

        comparison_result = comparison_result_label(curl_test, hsec_item)
        header_class = hsecscan_header_class(hsec_item) if hsec_item else None

        rows.append(
            {
                "header_key": key,
                "header_name": display_header_name(display_name),
                "priority": merge_priority(curl_test, hsec_item),
                "comparison_result": comparison_result,
                "curl_status_raw": curl_test.get("status") if curl_test else None,
                "curl_status": curl_status_label(curl_test.get("status") if curl_test else None),
                "curl_score_delta": curl_test.get("score_delta") if curl_test else None,
                "curl_reason": curl_test.get("reason") if curl_test else None,
                "curl_recommendation": curl_test.get("recommendation") if curl_test else None,
                "hsecscan_record_type": hsec_item.get("record_type") if hsec_item else None,
                "hsecscan_status": hsecscan_status_label(hsec_item),
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
            risk_rank(item.get("priority")),
            comparison_result_rank(item.get("comparison_result")),
            str(item.get("header_name") or "").lower(),
        )
    )

    return rows


def build_header_layer_comparison_summary(
    comparison_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Construye resumen para tarjetas de la GUI.
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