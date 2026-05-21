"""
professional_report_service.py
- Servicio de apoyo para el Reporte General Profesional de DASTXH.

Objetivo:
- Construir un reporte general editable a partir de una ejecución ya procesada.
- Preparar un resumen técnico compacto que pueda enviarse después a la IA.
- Generar una versión base determinística si la IA no está disponible.
- Normalizar el contenido recibido desde IA o formulario.
- Mantener separada la lógica de presentación profesional del detalle técnico.

Importante:
- Este archivo NO ejecuta herramientas externas.
- Este archivo NO ejecuta Dalfox.
- Este archivo NO ejecuta hsecscan.
- Este archivo NO llama todavía al modelo de IA.
- Este archivo NO genera PDF.
- Solo prepara contenido textual y estructuras para el reporte general.

Flujo esperado:
1. db.get_execution_detail(...) obtiene toda la información técnica.
2. professional_report_service construye:
   - payload editable del reporte;
   - contexto técnico resumido para IA;
   - fallback determinístico si la IA falla o no está habilitada.
3. db.save_professional_report(...) guarda la versión actual y crea historial.
4. Otro servicio posterior generará PDF desde la versión guardada.
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

    Se lee desde config.py para que el formulario, el servicio y la BD
    trabajen con la misma estructura.
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


def _yes_no(value: Any) -> str:
    """
    Convierte booleanos a Sí/No para texto de reporte.
    """
    return "Sí" if bool(value) else "No"


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
    Limita una lista para evitar textos demasiado largos en el contexto IA.
    """
    if not isinstance(items, list):
        return []

    return items[:max_items]


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


# ==========================================================
# NORMALIZACIÓN DE PAYLOAD EDITABLE
# ==========================================================

def build_empty_professional_report_payload() -> Dict[str, str]:
    """
    Construye un payload vacío con todos los campos editables.
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
# EXTRACCIÓN DE RESÚMENES TÉCNICOS DESDE detail
# ==========================================================

def _build_headers_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resume la verificación principal de cabeceras.
    """
    headers_evaluadas = _safe_int(detail.get("headers_evaluadas"))
    headers_presentes = _safe_int(detail.get("headers_presentes"))
    cumplimiento_pct = _safe_float(detail.get("cumplimiento_pct"))

    present_headers = detail.get("present_json") or []
    missing_headers = detail.get("missing_json") or []

    return {
        "headers_evaluadas": headers_evaluadas,
        "headers_presentes": headers_presentes,
        "headers_faltantes": max(headers_evaluadas - headers_presentes, 0),
        "cumplimiento_pct": cumplimiento_pct,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
    }


def _build_hsecscan_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resume la capa complementaria hsecscan.
    """
    hsecscan_summary_json = detail.get("hsecscan_summary_json") or {}
    hsecscan_class_summary = detail.get("hsecscan_class_summary") or {}
    comparison_summary = detail.get("header_layer_comparison_summary") or {}

    return {
        "enabled": bool(detail.get("enable_hsecscan")),
        "tool_rc": detail.get("hsecscan_rc"),
        "summary": hsecscan_summary_json,
        "class_summary": hsecscan_class_summary,
        "comparison_summary": comparison_summary,
        "checks_count": len(detail.get("hsecscan_checks") or []),
        "primary_count": _safe_int(hsecscan_class_summary.get("primary")),
        "complementary_count": _safe_int(hsecscan_class_summary.get("complementary")),
        "legacy_count": _safe_int(hsecscan_class_summary.get("legacy")),
        "other_observations_count": _safe_int(hsecscan_class_summary.get("other_observations")),
        "confirmed_count": _safe_int(comparison_summary.get("confirmed")),
        "discrepancies_count": _safe_int(comparison_summary.get("discrepancies")),
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

    return {
        "cookies_count": len(cookies),
        "risk_counts": risk_counts,
        "missing_secure": missing_secure,
        "missing_httponly": missing_httponly,
        "missing_samesite": missing_samesite,
        "sample_cookies": _limit_list(cookies, 8),
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

    return {
        "dalfox_rc": detail.get("dalfox_rc"),
        "findings_count_raw": _safe_int(detail.get("findings_count")),
        "xss_display_count": _safe_int(detail.get("xss_display_count")),
        "xss_display_mode": detail.get("xss_display_mode") or "-",
        "severity_counts": severity_counts,
        "sample_rows": _limit_list(
            [row for row in xss_display_rows if not row.get("is_placeholder")],
            8,
        ),
    }


def build_professional_report_ai_context(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye un contexto compacto para una futura llamada a IA.

    Este contexto evita enviar salidas crudas completas al modelo.
    Se envía solamente información estructurada y resumida.
    """
    headers_summary = _build_headers_summary(detail)
    hsecscan_summary = _build_hsecscan_summary(detail)
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
        "hsecscan": hsecscan_summary,
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
    """
    context = build_professional_report_ai_context(detail)

    execution = context["execution"]
    headers = context["headers"]
    hsecscan = context["hsecscan"]
    cookies = context["cookies"]
    xss = context["xss"]
    artifacts = context["artifacts"]

    target_url = _safe_text(execution.get("target_url"), "-")
    started_at = _safe_text(execution.get("started_at"), "-")
    finished_at = _safe_text(execution.get("finished_at"), "-")

    report_title = f"Reporte general DASTXH - Ejecución {execution.get('id')}"

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

    if cookies.get("cookies_count", 0) > 0:
        executive_summary_parts.append(
            f"También se observaron {cookies.get('cookies_count')} cookies evaluables, "
            "las cuales fueron revisadas considerando atributos como Secure, HttpOnly y SameSite."
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
            "El reporte se basa en la evidencia recolectada automáticamente durante la ejecución registrada.",
        ]
    )

    # ------------------------------------------------------
    # Metodología
    # ------------------------------------------------------
    methodology_text = "\n".join(
        [
            "La metodología aplicada por DASTXH se organiza en capas.",
            "",
            "1. Verificación principal con curl: obtiene cabeceras y cookies desde la respuesta HTTP.",
            "2. Evaluación de cabeceras: compara la respuesta contra el catálogo principal definido por DASTXH.",
            "3. Revisión de cookies: identifica atributos Secure, HttpOnly y SameSite, y clasifica riesgos mediante reglas internas.",
            "4. Contraste con hsecscan: aporta una segunda lectura técnica de cabeceras observadas o faltantes.",
            "5. Análisis XSS con Dalfox: ejecuta pruebas dinámicas sobre parámetros detectables y conserva evidencia técnica.",
            "6. Asistencia de IA: redacta interpretaciones o explicaciones sobre resultados ya calculados, sin sustituir la evidencia técnica original.",
        ]
    )

    # ------------------------------------------------------
    # Cabeceras
    # ------------------------------------------------------
    headers_analysis = "\n".join(
        [
            f"Cabeceras evaluadas: {headers.get('headers_evaluadas')}",
            f"Cabeceras presentes: {headers.get('headers_presentes')}",
            f"Cabeceras faltantes: {headers.get('headers_faltantes')}",
            f"Cumplimiento de cabeceras: {headers.get('cumplimiento_pct')}%",
            "",
            "Cabeceras presentes:",
            _bullet_lines([str(item) for item in headers.get("present_headers") or []]),
            "",
            "Cabeceras faltantes:",
            _bullet_lines([str(item) for item in headers.get("missing_headers") or []]),
        ]
    )

    # ------------------------------------------------------
    # hsecscan
    # ------------------------------------------------------
    if hsecscan.get("enabled"):
        hsecscan_analysis = "\n".join(
            [
                "hsecscan fue ejecutado como capa complementaria de contraste.",
                f"Código de retorno de herramienta: {hsecscan.get('tool_rc')}",
                f"Registros estructurados: {hsecscan.get('checks_count')}",
                f"Registros del catálogo principal: {hsecscan.get('primary_count')}",
                f"Observaciones complementarias vigentes: {hsecscan.get('complementary_count')}",
                f"Referencias históricas/obsoletas: {hsecscan.get('legacy_count')}",
                f"Discrepancias entre capas: {hsecscan.get('discrepancies_count')}",
                "",
                (
                    "Las observaciones de hsecscan se interpretan como respaldo técnico. "
                    "Las cabeceras históricas u obsoletas se conservan como referencia, "
                    "pero no penalizan el porcentaje principal de cumplimiento."
                ),
            ]
        )
    else:
        hsecscan_analysis = (
            "hsecscan no fue ejecutado o no se encontraba habilitado para esta ejecución. "
            "La evaluación de cabeceras se basa en la verificación principal realizada por DASTXH."
        )

    # ------------------------------------------------------
    # Cookies
    # ------------------------------------------------------
    cookies_analysis = "\n".join(
        [
            f"Cookies evaluables detectadas: {cookies.get('cookies_count')}",
            f"Cookies sin Secure: {cookies.get('missing_secure')}",
            f"Cookies sin HttpOnly: {cookies.get('missing_httponly')}",
            f"Cookies sin SameSite: {cookies.get('missing_samesite')}",
            "",
            "Distribución de riesgo:",
            f"- Alta: {cookies.get('risk_counts', {}).get('alta', 0)}",
            f"- Media: {cookies.get('risk_counts', {}).get('media', 0)}",
            f"- Baja: {cookies.get('risk_counts', {}).get('baja', 0)}",
            f"- Informativa: {cookies.get('risk_counts', {}).get('informativa', 0)}",
            "",
            (
                "La clasificación de cookies se basa en reglas internas alineadas con atributos "
                "de seguridad recomendados para reducir exposición de datos o sesiones."
            ),
        ]
    )

    # ------------------------------------------------------
    # XSS
    # ------------------------------------------------------
    if xss.get("xss_display_count", 0) > 0:
        xss_lines = [
            f"Hallazgos XSS mostrables: {xss.get('xss_display_count')}",
            f"Modo de visualización: {xss.get('xss_display_mode')}",
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
            "Los hallazgos XSS deben revisarse junto con la evidencia técnica generada por Dalfox "
            "para confirmar explotación, contexto y prioridad de corrección."
        )

        xss_analysis = "\n".join(xss_lines)
    else:
        xss_analysis = (
            "No se registraron hallazgos XSS válidos para mostrar en el resumen profesional. "
            "Esto no garantiza ausencia absoluta de vulnerabilidades; indica que, bajo las condiciones "
            "de esta ejecución, Dalfox no produjo evidencia estructurada suficiente para reportar un hallazgo."
        )

    # ------------------------------------------------------
    # Hallazgos priorizados
    # ------------------------------------------------------
    prioritized_items: List[str] = []

    if headers.get("headers_faltantes", 0) > 0:
        prioritized_items.append(
            f"Revisar cabeceras principales faltantes: {', '.join(headers.get('missing_headers') or [])}."
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

    if hsecscan.get("discrepancies_count", 0) > 0:
        prioritized_items.append(
            f"Revisar {hsecscan.get('discrepancies_count')} discrepancia(s) entre curl y hsecscan."
        )

    prioritized_findings = _bullet_lines(prioritized_items)

    # ------------------------------------------------------
    # Recomendaciones
    # ------------------------------------------------------
    general_recommendations = "\n".join(
        [
            "- Revisar e implementar las cabeceras principales faltantes según el contexto de la aplicación.",
            "- Validar que las cookies sensibles utilicen atributos Secure, HttpOnly y SameSite adecuados.",
            "- Analizar manualmente cualquier hallazgo XSS antes de clasificarlo como vulnerabilidad confirmada.",
            "- Usar la salida técnica y los artifacts como respaldo de la interpretación profesional.",
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
        ]
    )

    # ------------------------------------------------------
    # Conclusión
    # ------------------------------------------------------
    conclusion_text = (
        "La evaluación proporciona una vista consolidada del estado de seguridad HTTP, cookies y posibles hallazgos XSS "
        "para la URL analizada. El resultado debe utilizarse como evidencia de apoyo para priorizar revisiones técnicas, "
        "validar configuraciones y documentar acciones de mejora."
    )

    return normalize_professional_report_payload(
        {
            "report_title": report_title,
            "executive_summary": executive_summary,
            "scope_text": scope_text,
            "methodology_text": methodology_text,
            "headers_analysis": headers_analysis,
            "hsecscan_analysis": hsecscan_analysis,
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

    Si ya existe professional_report en BD, usa su contenido.
    Si no existe, genera un borrador determinístico todavía no persistido.
    """
    labels = get_professional_report_section_labels()
    help_texts = get_professional_report_help_texts()

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
        "current_version_number": current_version_number,
        "status": status,
        "updated_at": updated_at,
        "generated_by_ai": generated_by_ai,
        "ai_model_name": ai_model_name,
        "versions": detail.get("professional_report_versions") or [],
        "pdf_exports": detail.get("professional_report_pdf_exports") or [],
    }