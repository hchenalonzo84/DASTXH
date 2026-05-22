"""
professional_report_service.py
- Servicio de apoyo para el Reporte General Profesional de DASTXH.

Objetivo:
- Construir el contenido editable del reporte general.
- Preparar contexto técnico compacto para IA.
- Preparar tablas de evidencia objetiva para la pestaña Reporte general.
- Evitar duplicar información entre curl y hsecscan.
- Mantener la evidencia objetiva separada del texto editable.

Regla principal del reporte general:
- El texto editable interpreta.
- Las tablas debajo de cada sección evidencian.
- La evidencia se toma de los mismos datos ya mostrados en la pestaña Resumen.

Estructura recomendada:
1. Resumen ejecutivo
2. Alcance de la evaluación
3. Metodología aplicada
4. Análisis de cabeceras HTTP y contraste con hsecscan
   - Texto editable
   - Tabla de evidencia consolidada curl vs hsecscan
5. Análisis de cookies observadas
   - Texto editable
   - Tabla de evidencia de cookies
6. Análisis XSS
   - Texto editable
   - Tabla de evidencia XSS
7. Hallazgos priorizados
8. Recomendaciones generales
9. Limitaciones del análisis
10. Conclusión
11. Notas del analista

Importante:
- Este archivo NO ejecuta herramientas externas.
- Este archivo NO ejecuta Dalfox.
- Este archivo NO ejecuta hsecscan.
- Este archivo NO llama directamente al modelo de IA.
- Este archivo NO genera PDF.
- Solo prepara texto y estructuras de evidencia para GUI/PDF/IA.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import config


# ==========================================================
# CAMPOS EDITABLES DEL REPORTE GENERAL
# ==========================================================

def get_professional_report_fields() -> List[str]:
    """
    Devuelve la lista oficial de campos editables del reporte general.

    Se lee desde config.py para que:
    - formulario,
    - servicio,
    - IA,
    - PDF,
    - y BD

    trabajen con la misma estructura visible.
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
        "cookies_analysis",
        "xss_analysis",
        "prioritized_findings",
        "general_recommendations",
        "limitations_text",
        "conclusion_text",
        "analyst_notes",
    ]


def get_professional_report_section_labels() -> Dict[str, str]:
    """
    Devuelve etiquetas amigables para cada campo editable.
    """
    labels = getattr(config, "PROFESSIONAL_REPORT_SECTION_LABELS", {})

    if isinstance(labels, dict):
        return {str(k): str(v) for k, v in labels.items()}

    return {field: field for field in get_professional_report_fields()}


def get_professional_report_help_texts() -> Dict[str, str]:
    """
    Devuelve textos de ayuda para el formulario editable.
    """
    help_texts = getattr(config, "PROFESSIONAL_REPORT_SECTION_HELP_TEXTS", {})

    if isinstance(help_texts, dict):
        return {str(k): str(v) for k, v in help_texts.items()}

    return {field: "" for field in get_professional_report_fields()}


# ==========================================================
# HELPERS GENERALES
# ==========================================================

def _safe_text(value: Any, default: str = "") -> str:
    """
    Convierte un valor a texto seguro para usarlo en reportes.
    """
    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return text


def _safe_int(value: Any, default: int = 0) -> int:
    """
    Convierte un valor a entero con fallback.
    """
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """
    Convierte un valor a float con fallback.
    """
    try:
        return float(value)
    except Exception:
        return default


def _format_datetime(value: Any) -> str:
    """
    Formatea fechas de forma tolerante.

    Si el valor ya es string, se conserva.
    Si es datetime, se intenta usar strftime.
    """
    if value is None:
        return "-"

    if hasattr(value, "strftime"):
        try:
            return value.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(value)

    return str(value)


def _yes_no(value: Any) -> str:
    """
    Convierte booleanos a Sí/No para evidencia.
    """
    return "Sí" if bool(value) else "No"


def _bullet_lines(items: List[str]) -> str:
    """
    Convierte lista de textos en viñetas simples.
    """
    clean_items = [_safe_text(item) for item in items if _safe_text(item)]

    if not clean_items:
        return "- No se registraron elementos para esta sección."

    return "\n".join(f"- {item}" for item in clean_items)


def _limit_list(items: List[Any], max_items: int = 8) -> List[Any]:
    """
    Limita una lista para evitar textos demasiado largos en contexto IA.
    """
    if not isinstance(items, list):
        return []

    return items[:max_items]


def _truncate_text(value: Any, max_chars: int = 280) -> str:
    """
    Recorta textos largos para previews enviados a IA.
    """
    text = _safe_text(value)

    if len(text) <= max_chars:
        return text

    return text[:max_chars].rstrip() + "..."


def _first_non_empty(*values: Any, default: str = "-") -> str:
    """
    Devuelve el primer valor textual no vacío.
    """
    for value in values:
        text = _safe_text(value)

        if text:
            return text

    return default


def _count_by_risk(items: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Cuenta elementos por risk_level.
    """
    result = {
        "alta": 0,
        "media": 0,
        "baja": 0,
        "informativa": 0,
        "sin_clasificar": 0,
    }

    for item in items or []:
        risk = _safe_text(item.get("risk_level")).lower()

        if risk in result:
            result[risk] += 1
        else:
            result["sin_clasificar"] += 1

    return result


def _stringify_cwe_mappings(value: Any) -> str:
    """
    Convierte cwe_mappings a texto legible para evidencia.

    Acepta:
    - lista de diccionarios;
    - lista de strings;
    - string;
    - None.
    """
    if value is None:
        return "-"

    if isinstance(value, str):
        return value.strip() or "-"

    if isinstance(value, list):
        parts: List[str] = []

        for item in value:
            if isinstance(item, dict):
                cwe_id = _safe_text(item.get("cwe_id"))
                name = _safe_text(item.get("name"))

                if cwe_id and name:
                    parts.append(f"{cwe_id}: {name}")
                elif cwe_id:
                    parts.append(cwe_id)
                elif name:
                    parts.append(name)
            else:
                text = _safe_text(item)

                if text:
                    parts.append(text)

        return "; ".join(parts) if parts else "-"

    return str(value)


# ==========================================================
# NORMALIZACIÓN DE PAYLOAD EDITABLE
# ==========================================================

def build_empty_professional_report_payload() -> Dict[str, str]:
    """
    Construye un payload vacío con todos los campos editables visibles.
    """
    payload: Dict[str, str] = {}

    for field in get_professional_report_fields():
        payload[field] = ""

    payload["report_title"] = getattr(
        config,
        "PROFESSIONAL_REPORT_DEFAULT_TITLE",
        "Reporte general DASTXH",
    )

    return payload


def normalize_professional_report_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Normaliza un payload recibido del formulario o de IA.

    Esto evita que falten campos al guardar en BD.

    Nota:
    - hsecscan_analysis ya no se muestra como campo editable visible.
    - La sección combinada usa headers_analysis.
    """
    normalized = build_empty_professional_report_payload()

    if not isinstance(payload, dict):
        return normalized

    for field in get_professional_report_fields():
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


def merge_generated_payload_with_fallback(
    generated_payload: Optional[Dict[str, Any]],
    fallback_payload: Dict[str, Any],
) -> Dict[str, str]:
    """
    Mezcla una respuesta generada por IA con un fallback determinístico.

    Regla:
    - Si IA devuelve una sección vacía, se conserva el fallback.
    - Si IA devuelve una sección con contenido, se usa esa versión.
    """
    fallback = normalize_professional_report_payload(fallback_payload)

    if not isinstance(generated_payload, dict):
        return fallback

    merged = dict(fallback)

    for field in get_professional_report_fields():
        value = generated_payload.get(field)

        if value is None:
            continue

        text = str(value).strip()

        if text:
            merged[field] = text

    if not merged.get("report_title", "").strip():
        merged["report_title"] = fallback.get(
            "report_title",
            getattr(config, "PROFESSIONAL_REPORT_DEFAULT_TITLE", "Reporte general DASTXH"),
        )

    return normalize_professional_report_payload(merged)
# ==========================================================
# TABLAS DE EVIDENCIA OBJETIVA
# ==========================================================

def build_headers_evidence_rows(detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Construye la evidencia consolidada de cabeceras HTTP.

    Fuente principal:
    - detail.header_layer_comparison

    Esta es la misma comparación usada en la pestaña Resumen:
    curl vs hsecscan.

    Regla:
    - No se separa evidencia curl y evidencia hsecscan.
    - Se muestra evidencia consolidada para evitar duplicidad.
    - Se incluyen CWE, interpretación y recomendación cuando existen.
    """
    comparison_rows = detail.get("header_layer_comparison") or []
    evidence_rows: List[Dict[str, Any]] = []

    for item in comparison_rows:
        if not isinstance(item, dict):
            continue

        interpretation = _first_non_empty(
            item.get("hsecscan_description_es"),
            item.get("hsecscan_description"),
            item.get("curl_reason"),
            default="-",
        )

        recommendation = _first_non_empty(
            item.get("hsecscan_recommendation_es"),
            item.get("hsecscan_recommendation"),
            item.get("curl_recommendation"),
            default="-",
        )

        cwe = _first_non_empty(
            item.get("hsecscan_cwe_es"),
            item.get("hsecscan_cwe"),
            default="-",
        )

        evidence_rows.append(
            {
                "header_name": _safe_text(item.get("header_name"), "-"),
                "classification": _safe_text(
                    item.get("hsecscan_header_class_label"),
                    "Catálogo principal DASTXH",
                ),
                "curl_status": _safe_text(item.get("curl_status"), "No evaluada"),
                "hsecscan_status": _safe_text(item.get("hsecscan_status"), "No reportada"),
                "comparison_result": _safe_text(item.get("comparison_result"), "-"),
                "priority": _safe_text(item.get("priority"), "informativa"),
                "cwe": cwe,
                "interpretation": interpretation,
                "recommendation": recommendation,
            }
        )

    return evidence_rows


def build_cookie_evidence_rows(detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Construye la tabla de evidencia de cookies.

    Fuente:
    - detail.cookies_flags_json

    Esta tabla debe coincidir conceptualmente con la pestaña Resumen.
    """
    cookies = detail.get("cookies_flags_json") or []
    evidence_rows: List[Dict[str, Any]] = []

    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue

        samesite_present = cookie.get("samesite_present")

        if samesite_present is None:
            samesite_present = cookie.get("samesite")

        evidence_rows.append(
            {
                "cookie": _first_non_empty(
                    cookie.get("cookie_name"),
                    cookie.get("cookie_raw"),
                    cookie.get("cookie"),
                    default="-",
                ),
                "secure": _yes_no(cookie.get("secure")),
                "httponly": _yes_no(cookie.get("httponly")),
                "samesite": _yes_no(samesite_present),
                "samesite_value": _safe_text(cookie.get("samesite_value"), "-"),
                "risk_level": _safe_text(cookie.get("risk_level"), "-"),
                "cwe": _stringify_cwe_mappings(cookie.get("cwe_mappings")),
                "interpretation": _safe_text(cookie.get("interpretation_humana"), "-"),
                "recommendation": _safe_text(cookie.get("recommended_action"), "-"),
            }
        )

    return evidence_rows


def build_xss_evidence_rows(detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Construye la tabla de evidencia XSS.

    Fuente:
    - detail.xss_display_rows

    Esta es la misma evidencia objetiva que se muestra en Resumen:
    parámetro, payload, evidencia reflejada, severidad e interpretación IA.
    """
    xss_rows = detail.get("xss_display_rows") or []
    evidence_rows: List[Dict[str, Any]] = []

    for item in xss_rows:
        if not isinstance(item, dict):
            continue

        if item.get("is_placeholder"):
            continue

        evidence_rows.append(
            {
                "row_order": _safe_text(item.get("row_order"), "-"),
                "parameter": _safe_text(item.get("parameter"), "-"),
                "payload": _safe_text(item.get("payload"), "-"),
                "evidence": _safe_text(item.get("evidence"), "-"),
                "severity": _safe_text(item.get("severity"), "-"),
                "occurrences": _safe_text(item.get("occurrences"), "1"),
                "interpretation": _safe_text(item.get("interpretation_humana"), "-"),
                "risk_summary": _safe_text(item.get("risk_summary"), "-"),
                "likely_root_cause": _safe_text(item.get("likely_root_cause"), "-"),
                "recommended_review_area": _safe_text(item.get("recommended_review_area"), "-"),
            }
        )

    return evidence_rows


def build_professional_report_evidence_tables(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye todas las tablas de evidencia objetiva para el Reporte general.

    Estas tablas serán usadas por:
    - execution_detail.html
    - professional_report_pdf_service.py
    - contexto compacto para IA
    """
    enabled = bool(getattr(config, "PROFESSIONAL_REPORT_EVIDENCE_ENABLED", True))

    headers_rows = build_headers_evidence_rows(detail)
    cookies_rows = build_cookie_evidence_rows(detail)
    xss_rows = build_xss_evidence_rows(detail)

    return {
        "enabled": enabled,
        "headers": {
            "title": getattr(
                config,
                "PROFESSIONAL_REPORT_HEADERS_EVIDENCE_TITLE",
                "Evidencia consolidada curl vs hsecscan",
            ),
            "rows": headers_rows,
            "count": len(headers_rows),
        },
        "cookies": {
            "title": getattr(
                config,
                "PROFESSIONAL_REPORT_COOKIES_EVIDENCE_TITLE",
                "Evidencia de cookies observadas",
            ),
            "rows": cookies_rows,
            "count": len(cookies_rows),
        },
        "xss": {
            "title": getattr(
                config,
                "PROFESSIONAL_REPORT_XSS_EVIDENCE_TITLE",
                "Evidencia de hallazgos XSS",
            ),
            "rows": xss_rows,
            "count": len(xss_rows),
        },
    }


# ==========================================================
# EXTRACCIÓN DE RESÚMENES TÉCNICOS DESDE detail
# ==========================================================

def _build_headers_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resume la verificación principal de cabeceras y su comparación.
    """
    headers_evaluadas = _safe_int(detail.get("headers_evaluadas"))
    headers_presentes = _safe_int(detail.get("headers_presentes"))
    cumplimiento_pct = _safe_float(detail.get("cumplimiento_pct"))

    present_headers = detail.get("present_json") or []
    missing_headers = detail.get("missing_json") or []

    comparison_summary = detail.get("header_layer_comparison_summary") or {}
    hsecscan_class_summary = detail.get("hsecscan_class_summary") or {}

    headers_evidence = build_headers_evidence_rows(detail)

    return {
        "headers_evaluadas": headers_evaluadas,
        "headers_presentes": headers_presentes,
        "headers_faltantes": max(headers_evaluadas - headers_presentes, 0),
        "cumplimiento_pct": cumplimiento_pct,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "comparison_summary": comparison_summary,
        "hsecscan_class_summary": hsecscan_class_summary,
        "evidence_count": len(headers_evidence),
        "evidence_preview": _limit_list(headers_evidence, 6),
    }


def _build_cookies_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resume cookies observadas e interpretadas.
    """
    cookies = detail.get("cookies_flags_json") or []
    risk_counts = _count_by_risk(cookies)

    missing_secure = 0
    missing_httponly = 0
    missing_samesite = 0

    for cookie in cookies:
        if not bool(cookie.get("secure")):
            missing_secure += 1

        if not bool(cookie.get("httponly")):
            missing_httponly += 1

        samesite_present = cookie.get("samesite_present")

        if samesite_present is None:
            samesite_present = cookie.get("samesite")

        if not bool(samesite_present):
            missing_samesite += 1

    cookie_evidence = build_cookie_evidence_rows(detail)

    return {
        "cookies_count": len(cookies),
        "risk_counts": risk_counts,
        "missing_secure": missing_secure,
        "missing_httponly": missing_httponly,
        "missing_samesite": missing_samesite,
        "evidence_count": len(cookie_evidence),
        "evidence_preview": _limit_list(cookie_evidence, 6),
    }


def _build_xss_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resume hallazgos XSS mostrables.
    """
    xss_display_rows = detail.get("xss_display_rows") or []

    severity_counts: Dict[str, int] = {}

    for item in xss_display_rows:
        if item.get("is_placeholder"):
            continue

        severity = _safe_text(item.get("severity"), "sin_clasificar")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    xss_evidence = build_xss_evidence_rows(detail)

    return {
        "dalfox_rc": detail.get("dalfox_rc"),
        "findings_count_raw": _safe_int(detail.get("findings_count")),
        "xss_display_count": _safe_int(detail.get("xss_display_count")),
        "xss_display_mode": detail.get("xss_display_mode") or "-",
        "severity_counts": severity_counts,
        "evidence_count": len(xss_evidence),
        "evidence_preview": _limit_list(xss_evidence, 6),
    }


def build_professional_report_ai_context(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye un contexto compacto para una futura llamada a IA.

    Importante:
    - No se envía salida cruda completa.
    - Se envían resúmenes y muestras pequeñas de evidencia.
    - La IA debe redactar interpretación, no inventar evidencia.
    """
    headers_summary = _build_headers_summary(detail)
    cookies_summary = _build_cookies_summary(detail)
    xss_summary = _build_xss_summary(detail)

    return {
        "execution": {
            "id": detail.get("id"),
            "target_url": detail.get("target_url"),
            "status": detail.get("status"),
            "request_source": detail.get("request_source"),
            "flow": "Evaluación profunda controlada",
            "started_at": _format_datetime(detail.get("started_at")),
            "finished_at": _format_datetime(detail.get("finished_at")),
        },
        "headers": headers_summary,
        "cookies": cookies_summary,
        "xss": xss_summary,
        "artifacts": {
            "count": len(detail.get("artifacts") or []),
            "files": [
                {
                    "type": item.get("artifact_type"),
                    "file_name": item.get("file_name"),
                    "relative_path": item.get("relative_path"),
                }
                for item in _limit_list(detail.get("artifacts") or [], 12)
            ],
        },
    }
# ==========================================================
# CONSTRUCCIÓN DETERMINÍSTICA DEL REPORTE GENERAL
# ==========================================================

def build_deterministic_professional_report_payload(detail: Dict[str, Any]) -> Dict[str, str]:
    """
    Construye una versión base del reporte general sin IA.

    Esta versión sirve como:
    - fallback si la IA no está disponible;
    - borrador inicial editable;
    - base para mezclar con respuesta IA.

    Regla:
    - El texto interpreta.
    - La evidencia objetiva NO se repite dentro del textarea.
    - Las tablas de evidencia se muestran debajo de cada sección.
    """
    context = build_professional_report_ai_context(detail)

    execution = context["execution"]
    headers = context["headers"]
    cookies = context["cookies"]
    xss = context["xss"]
    artifacts = context["artifacts"]

    target_url = _safe_text(execution.get("target_url"), "-")
    started_at = _safe_text(execution.get("started_at"), "-")
    finished_at = _safe_text(execution.get("finished_at"), "-")

    report_title = f"Reporte general DASTXH - Ejecución {execution.get('id')}"

    comparison_summary = headers.get("comparison_summary") or {}
    hsecscan_class_summary = headers.get("hsecscan_class_summary") or {}

    confirmed_count = _safe_int(comparison_summary.get("confirmed"))
    discrepancies_count = _safe_int(comparison_summary.get("discrepancies"))
    complementary_count = _safe_int(comparison_summary.get("complementary"))
    legacy_count = _safe_int(comparison_summary.get("legacy"))
    evidence_header_count = _safe_int(headers.get("evidence_count"))

    # ------------------------------------------------------
    # Resumen ejecutivo
    # ------------------------------------------------------
    executive_summary_parts = [
        f"Se realizó una evaluación dinámica de seguridad web sobre la URL objetivo: {target_url}.",
        (
            "El flujo aplicado corresponde a una evaluación profunda controlada, "
            "integrando verificación de cabeceras HTTP, revisión de cookies, "
            "contraste complementario con hsecscan y análisis de posibles hallazgos XSS con Dalfox."
        ),
        (
            f"El cumplimiento de cabeceras registrado por la verificación principal fue de "
            f"{headers.get('cumplimiento_pct')}%, con "
            f"{headers.get('headers_presentes')} cabeceras presentes de "
            f"{headers.get('headers_evaluadas')} evaluadas."
        ),
    ]

    if evidence_header_count > 0:
        executive_summary_parts.append(
            f"La evidencia consolidada de cabeceras contiene {evidence_header_count} fila(s) comparativas "
            "entre curl y hsecscan, usadas como respaldo objetivo del análisis."
        )

    if cookies.get("cookies_count", 0) > 0:
        executive_summary_parts.append(
            f"También se observaron {cookies.get('cookies_count')} cookies evaluables, "
            "revisadas considerando atributos como Secure, HttpOnly y SameSite."
        )
    else:
        executive_summary_parts.append(
            "No se detectaron cookies evaluables en la respuesta final analizada."
        )

    if xss.get("xss_display_count", 0) > 0:
        executive_summary_parts.append(
            f"En la capa XSS se registraron {xss.get('xss_display_count')} hallazgos mostrables "
            "para revisión técnica."
        )
    else:
        executive_summary_parts.append(
            "En la capa XSS no se registraron hallazgos válidos para mostrar en el resumen profesional."
        )

    executive_summary = "\n\n".join(executive_summary_parts)

    # ------------------------------------------------------
    # Alcance
    # ------------------------------------------------------
    scope_text = "\n".join(
        [
            f"URL evaluada: {target_url}",
            f"Fecha/hora de inicio: {started_at}",
            f"Fecha/hora de finalización: {finished_at}",
            "Tipo de evaluación: caja negra desde la perspectiva del prototipo DASTXH.",
            "Capas consideradas: cabeceras HTTP, cookies, hsecscan como contraste complementario y Dalfox para XSS.",
            (
                "El reporte se basa en la evidencia recolectada automáticamente durante la ejecución registrada. "
                "La evidencia objetiva se muestra en tablas debajo de las secciones principales."
            ),
        ]
    )

    # ------------------------------------------------------
    # Metodología
    # ------------------------------------------------------
    methodology_text = "\n".join(
        [
            "La metodología aplicada por DASTXH se organiza en capas complementarias.",
            "",
            "1. Verificación principal con curl: obtiene cabeceras y cookies desde la respuesta HTTP.",
            "2. Evaluación de cabeceras: compara la respuesta contra el catálogo principal definido por DASTXH.",
            "3. Revisión de cookies: identifica atributos Secure, HttpOnly y SameSite, y clasifica riesgos mediante reglas internas.",
            "4. Contraste con hsecscan: aporta una segunda lectura técnica sobre cabeceras observadas, faltantes o complementarias.",
            "5. Análisis XSS con Dalfox: ejecuta pruebas dinámicas sobre parámetros detectables y conserva evidencia técnica.",
            "6. Asistencia de IA: redacta interpretaciones o explicaciones sobre resultados ya calculados, sin sustituir la evidencia técnica original.",
            "",
            (
                "En el reporte general, la evidencia no se presenta como salida cruda de terminal. "
                "Se resume en tablas verificables tomadas de la vista Resumen."
            ),
        ]
    )

    # ------------------------------------------------------
    # Cabeceras HTTP + hsecscan
    # ------------------------------------------------------
    headers_analysis = "\n".join(
        [
            (
                "La evaluación de cabeceras se interpreta de forma consolidada. "
                "curl funciona como fuente principal para calcular el cumplimiento de cabeceras, "
                "mientras que hsecscan se utiliza como una capa de contraste para confirmar, complementar "
                "o identificar diferencias técnicas."
            ),
            "",
            f"Cumplimiento de cabeceras: {headers.get('cumplimiento_pct')}%.",
            f"Cabeceras evaluadas: {headers.get('headers_evaluadas')}.",
            f"Cabeceras presentes: {headers.get('headers_presentes')}.",
            f"Cabeceras faltantes: {headers.get('headers_faltantes')}.",
            "",
            (
                f"La comparación consolidada registró {evidence_header_count} fila(s) de evidencia. "
                f"De ellas, {confirmed_count} aparecen confirmadas por curl y hsecscan, "
                f"{discrepancies_count} requieren revisión por discrepancia, "
                f"{complementary_count} corresponden a observaciones complementarias y "
                f"{legacy_count} a referencias históricas u obsoletas."
            ),
            "",
            (
                "La tabla de evidencia ubicada debajo de esta sección contiene el detalle objetivo "
                "por cabecera: clasificación, resultado de curl, resultado de hsecscan, resultado consolidado, "
                "prioridad, CWE asociado cuando está disponible, interpretación técnica y recomendación."
            ),
            "",
            (
                "Las referencias históricas u obsoletas reportadas por hsecscan se conservan como evidencia "
                "informativa, pero no penalizan el porcentaje principal de cumplimiento."
            ),
        ]
    )

    # ------------------------------------------------------
    # Cookies
    # ------------------------------------------------------
    cookies_analysis = "\n".join(
        [
            (
                "La revisión de cookies identifica atributos de seguridad relevantes para reducir exposición "
                "de sesiones, tokens o datos asociados al navegador."
            ),
            "",
            f"Cookies evaluables detectadas: {cookies.get('cookies_count')}.",
            f"Cookies sin Secure: {cookies.get('missing_secure')}.",
            f"Cookies sin HttpOnly: {cookies.get('missing_httponly')}.",
            f"Cookies sin SameSite: {cookies.get('missing_samesite')}.",
            "",
            "Distribución de riesgo:",
            f"- Alta: {cookies.get('risk_counts', {}).get('alta', 0)}",
            f"- Media: {cookies.get('risk_counts', {}).get('media', 0)}",
            f"- Baja: {cookies.get('risk_counts', {}).get('baja', 0)}",
            f"- Informativa: {cookies.get('risk_counts', {}).get('informativa', 0)}",
            "",
            (
                "La tabla de evidencia ubicada debajo de esta sección muestra, por cada cookie, "
                "los atributos Secure, HttpOnly y SameSite, el riesgo asignado, CWE asociado, "
                "interpretación y recomendación."
            ),
        ]
    )

    # ------------------------------------------------------
    # XSS
    # ------------------------------------------------------
    if xss.get("xss_display_count", 0) > 0:
        xss_lines = [
            (
                "El análisis XSS presenta los hallazgos mostrables generados a partir de la evidencia "
                "estructurada de Dalfox y su interpretación asistida."
            ),
            "",
            f"Hallazgos XSS mostrables: {xss.get('xss_display_count')}.",
            f"Modo de visualización: {xss.get('xss_display_mode')}.",
            "",
            "Distribución de severidad:",
        ]

        severity_counts = xss.get("severity_counts") or {}

        if severity_counts:
            for severity, count in severity_counts.items():
                xss_lines.append(f"- {severity}: {count}")
        else:
            xss_lines.append("- No se registró una distribución de severidad.")

        xss_lines.append("")
        xss_lines.append(
            "La tabla de evidencia ubicada debajo de esta sección muestra los elementos objetivos "
            "del hallazgo: parámetro, payload, evidencia reflejada, severidad, interpretación, "
            "riesgo, causa probable y área recomendada para revisión."
        )

        xss_lines.append("")
        xss_lines.append(
            "Estos hallazgos deben revisarse manualmente antes de clasificarse como vulnerabilidades "
            "confirmadas en un entorno real."
        )

        xss_analysis = "\n".join(xss_lines)
    else:
        xss_analysis = "\n".join(
            [
                (
                    "No se registraron hallazgos XSS válidos para mostrar en el resumen profesional. "
                    "Esto no garantiza ausencia absoluta de vulnerabilidades; indica que, bajo las condiciones "
                    "de esta ejecución, Dalfox no produjo evidencia estructurada suficiente para reportar un hallazgo."
                ),
                "",
                (
                    "Si existiera evidencia técnica posterior, debería revisarse en los artifacts de Dalfox "
                    "y contrastarse manualmente antes de incluirla como hallazgo confirmado."
                ),
            ]
        )

    # ------------------------------------------------------
    # Hallazgos priorizados
    # ------------------------------------------------------
    prioritized_items: List[str] = []

    if headers.get("headers_faltantes", 0) > 0:
        missing_headers = headers.get("missing_headers") or []
        missing_headers_text = ", ".join(str(item) for item in missing_headers)

        if missing_headers_text:
            prioritized_items.append(
                f"Revisar cabeceras principales faltantes: {missing_headers_text}."
            )
        else:
            prioritized_items.append(
                "Revisar cabeceras principales faltantes detectadas por el catálogo DASTXH."
            )

    if discrepancies_count > 0:
        prioritized_items.append(
            f"Revisar {discrepancies_count} discrepancia(s) entre curl y hsecscan."
        )

    if cookies.get("missing_httponly", 0) > 0:
        prioritized_items.append(
            f"Revisar {cookies.get('missing_httponly')} cookie(s) sin HttpOnly."
        )

    if cookies.get("missing_secure", 0) > 0:
        prioritized_items.append(
            f"Revisar {cookies.get('missing_secure')} cookie(s) sin Secure."
        )

    if cookies.get("missing_samesite", 0) > 0:
        prioritized_items.append(
            f"Revisar {cookies.get('missing_samesite')} cookie(s) sin SameSite."
        )

    if xss.get("xss_display_count", 0) > 0:
        prioritized_items.append(
            f"Validar manualmente los {xss.get('xss_display_count')} hallazgo(s) XSS mostrables."
        )

    prioritized_findings = _bullet_lines(prioritized_items)

    # ------------------------------------------------------
    # Recomendaciones
    # ------------------------------------------------------
    general_recommendations = "\n".join(
        [
            "- Revisar e implementar las cabeceras principales faltantes según el contexto de la aplicación.",
            "- Usar la tabla consolidada curl vs hsecscan para distinguir hallazgos confirmados, discrepancias y observaciones complementarias.",
            "- Validar que las cookies sensibles utilicen atributos Secure, HttpOnly y SameSite adecuados.",
            "- Analizar manualmente cualquier hallazgo XSS antes de clasificarlo como vulnerabilidad confirmada.",
            "- Usar los artifacts técnicos como respaldo adicional cuando se requiera revisar la salida cruda de las herramientas.",
            "- Repetir la evaluación después de aplicar correcciones para verificar mejoras.",
        ]
    )

    # ------------------------------------------------------
    # Limitaciones
    # ------------------------------------------------------
    limitations_text = "\n".join(
        [
            "La evaluación se realizó desde una perspectiva de caja negra y depende de la respuesta observada durante la ejecución.",
            "Los sitios públicos pueden responder de forma variable por latencia, protección anti-bots, bloqueos, redirecciones o reglas del servidor.",
            "hsecscan se utiliza como capa complementaria y puede reportar cabeceras históricas u obsoletas que no forman parte del cumplimiento principal.",
            "La ausencia de hallazgos XSS en una ejecución no garantiza ausencia absoluta de vulnerabilidades.",
            "Las interpretaciones generadas por IA deben ser revisadas por una persona antes de usarse en un informe final.",
            "Las tablas del reporte general resumen la evidencia objetiva; la salida completa de terminal permanece disponible en los artifacts técnicos.",
        ]
    )

    # ------------------------------------------------------
    # Conclusión
    # ------------------------------------------------------
    conclusion_text = (
        "La evaluación proporciona una vista consolidada del estado de seguridad HTTP, cookies y posibles hallazgos XSS "
        "para la URL analizada. El reporte general combina interpretación editable con evidencia objetiva resumida, "
        "permitiendo respaldar las conclusiones sin depender únicamente de texto descriptivo."
    )

    return normalize_professional_report_payload(
        {
            "report_title": report_title,
            "executive_summary": executive_summary,
            "scope_text": scope_text,
            "methodology_text": methodology_text,
            "headers_analysis": headers_analysis,
            "cookies_analysis": cookies_analysis,
            "xss_analysis": xss_analysis,
            "prioritized_findings": prioritized_findings,
            "general_recommendations": general_recommendations,
            "limitations_text": limitations_text,
            "conclusion_text": conclusion_text,
            "analyst_notes": "",
        }
    )
# ==========================================================
# CONTEXTO DE FORMULARIO PARA LA GUI
# ==========================================================

def build_professional_report_view_context(
    detail: Dict[str, Any],
    current_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Construye contexto para renderizar la pestaña Reporte general.

    Si ya existe professional_report en BD:
    - usa su contenido editable actual.

    Si no existe:
    - genera un borrador determinístico todavía no persistido.

    Además:
    - agrega tablas de evidencia objetiva debajo de las secciones principales.
    """
    labels = get_professional_report_section_labels()
    help_texts = get_professional_report_help_texts()
    evidence_tables = build_professional_report_evidence_tables(detail)

    if current_report:
        payload = normalize_professional_report_payload(current_report)
        exists = True
        current_version_number = current_report.get("current_version_number") or 0
        status = current_report.get("status") or "draft"
        updated_at = current_report.get("updated_at")
        generated_by_ai = bool(current_report.get("generated_by_ai"))
        ai_model_name = current_report.get("ai_model_name")
    else:
        payload = build_deterministic_professional_report_payload(detail)
        exists = False
        current_version_number = 0
        status = "not_saved"
        updated_at = None
        generated_by_ai = False
        ai_model_name = None

    return {
        "exists": exists,
        "fields": get_professional_report_fields(),
        "labels": labels,
        "help_texts": help_texts,
        "payload": payload,
        "evidence": evidence_tables,
        "current_version_number": current_version_number,
        "status": status,
        "updated_at": updated_at,
        "generated_by_ai": generated_by_ai,
        "ai_model_name": ai_model_name,
        "versions": detail.get("professional_report_versions") or [],
        "pdf_exports": detail.get("professional_report_pdf_exports") or [],
    }


# ==========================================================
# HELPERS PARA PDF
# ==========================================================

def build_professional_report_pdf_context(
    detail: Dict[str, Any],
    snapshot_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Construye un contexto listo para el servicio PDF.

    Se mantiene en este servicio para que GUI y PDF usen la misma evidencia.
    """
    return {
        "payload": normalize_professional_report_payload(snapshot_payload),
        "labels": get_professional_report_section_labels(),
        "fields": get_professional_report_fields(),
        "evidence": build_professional_report_evidence_tables(detail),
    }