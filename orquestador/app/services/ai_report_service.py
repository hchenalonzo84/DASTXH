"""
ai_report_service.py
- Servicio de IA para generar el Reporte General Profesional de DASTXH.

Objetivo:
- Tomar datos técnicos ya procesados por DASTXH.
- Enviar un contexto compacto al modelo local.
- Solicitar una redacción profesional inicial para el reporte general.
- Devolver un payload editable compatible con professional_reports.
- Usar fallback determinístico si la IA falla, está desactivada o responde mal.

Regla actual del Reporte General:
- El texto editable interpreta los resultados.
- Las tablas de evidencia objetiva se muestran debajo de cada sección.
- La IA NO debe copiar toda la evidencia dentro del texto.
- La IA debe redactar conclusiones, contexto y explicación profesional.
- Las evidencias de cabeceras, cookies y XSS se cargan desde professional_report_service.py.

Importante:
- La IA NO decide riesgos desde cero.
- La IA NO ejecuta herramientas.
- La IA NO modifica la base de datos.
- La IA NO reemplaza la evidencia técnica.
- La IA NO debe inventar cabeceras, cookies, CWE, payloads ni hallazgos.
- La IA solo redacta secciones profesionales a partir de datos ya calculados.

Flujo esperado:
1. professional_report_service construye un contexto técnico resumido.
2. ai_report_service envía ese contexto al modelo local.
3. El modelo devuelve JSON con las secciones editables visibles.
4. Si el JSON es válido, se mezcla con el fallback determinístico.
5. Si algo falla, se usa el fallback determinístico.
6. webapp.py guarda el resultado usando db.save_professional_report(...).

Variables .env soportadas:
- DASTXH_REPORT_AI_ENABLED
- DASTXH_REPORT_AI_BASE_URL
- DASTXH_REPORT_AI_MODEL
- DASTXH_REPORT_AI_API_KEY
- DASTXH_REPORT_AI_TIMEOUT_SECONDS
- DASTXH_REPORT_AI_TEMPERATURE
- DASTXH_REPORT_AI_MAX_OUTPUT_TOKENS

Si esas variables no existen, se reutilizan las generales:
- DASTXH_AI_ENABLED
- DASTXH_AI_BASE_URL
- DASTXH_AI_MODEL
- DASTXH_AI_API_KEY
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict

from services.professional_report_service import (
    build_deterministic_professional_report_payload,
    build_professional_report_ai_context,
    get_professional_report_fields,
    merge_generated_payload_with_fallback,
    normalize_professional_report_payload,
)


# ==========================================================
# CONFIGURACIÓN DESDE ENTORNO
# ==========================================================

def _env_text(name: str, default: str = "") -> str:
    """
    Lee una variable de entorno como texto.
    """
    value = os.getenv(name)

    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return text


def _env_bool(name: str, default: bool = False) -> bool:
    """
    Lee una variable de entorno como booleano.
    """
    value = os.getenv(name)

    if value is None:
        return default

    text = str(value).strip().lower()

    return text in ("1", "true", "yes", "y", "on", "si", "sí")


def _env_int(name: str, default: int) -> int:
    """
    Lee una variable de entorno como entero.
    """
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(str(value).strip())
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    """
    Lee una variable de entorno como número decimal.
    """
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return float(str(value).strip())
    except Exception:
        return default


def _is_report_ai_enabled() -> bool:
    """
    Determina si la generación IA de reporte general está habilitada.

    Primero revisa variable específica del reporte.
    Si no existe, usa la variable general DASTXH_AI_ENABLED.
    """
    if os.getenv("DASTXH_REPORT_AI_ENABLED") is not None:
        return _env_bool("DASTXH_REPORT_AI_ENABLED", False)

    return _env_bool("DASTXH_AI_ENABLED", False)


def _get_report_ai_base_url() -> str:
    """
    Obtiene el endpoint base OpenAI-compatible.
    """
    return _env_text(
        "DASTXH_REPORT_AI_BASE_URL",
        _env_text("DASTXH_AI_BASE_URL", "http://model-runner.docker.internal:12434/engines/v1"),
    )


def _get_report_ai_model() -> str:
    """
    Obtiene el nombre del modelo a usar.
    """
    return _env_text(
        "DASTXH_REPORT_AI_MODEL",
        _env_text("DASTXH_AI_MODEL", "ai/llama3.2"),
    )


def _get_report_ai_api_key() -> str:
    """
    Obtiene API key para endpoint compatible.

    Docker Model Runner normalmente no requiere una llave real,
    pero el formato OpenAI-compatible suele esperar el header Authorization.
    """
    return _env_text(
        "DASTXH_REPORT_AI_API_KEY",
        _env_text("DASTXH_AI_API_KEY", "not-needed"),
    )


def _get_report_ai_timeout_seconds() -> int:
    """
    Timeout por llamada IA para reporte general.
    """
    return _env_int("DASTXH_REPORT_AI_TIMEOUT_SECONDS", 300)


def _get_report_ai_temperature() -> float:
    """
    Temperatura baja para respuestas estables.
    """
    return _env_float("DASTXH_REPORT_AI_TEMPERATURE", 0.15)


def _get_report_ai_max_output_tokens() -> int:
    """
    Máximo de tokens de salida para el reporte general.
    """
    return _env_int("DASTXH_REPORT_AI_MAX_OUTPUT_TOKENS", 2600)


def _chat_completions_url(base_url: str) -> str:
    """
    Construye URL final /chat/completions.
    """
    clean_base = str(base_url or "").strip().rstrip("/")
    return f"{clean_base}/chat/completions"
# ==========================================================
# PROMPTS
# ==========================================================

def _build_system_prompt() -> str:
    """
    Prompt de sistema para controlar el comportamiento de la IA.

    La IA debe generar texto editable, no tablas de evidencia.
    Las tablas se muestran aparte en la GUI y en el PDF.
    """
    fields = get_professional_report_fields()
    fields_text = ", ".join(fields)

    return (
        "Eres un asistente técnico que redacta reportes profesionales de seguridad web "
        "para el prototipo académico DASTXH.\n\n"
        "Debes escribir en español latino, con tono formal, claro y profesional.\n\n"
        "Contexto de funcionamiento del reporte:\n"
        "- El Reporte General tiene campos editables de texto.\n"
        "- Debajo de las secciones de cabeceras, cookies y XSS se muestran tablas de evidencia objetiva.\n"
        "- Tu tarea es redactar interpretación profesional, no duplicar toda la evidencia dentro del texto.\n"
        "- Puedes mencionar que la evidencia objetiva se muestra en la tabla correspondiente.\n\n"
        "Reglas obligatorias:\n"
        "1. No inventes hallazgos.\n"
        "2. No inventes cabeceras, cookies, payloads, CWE, porcentajes ni conteos.\n"
        "3. No afirmes vulnerabilidades no respaldadas por los datos.\n"
        "4. No cambies porcentajes, conteos ni resultados técnicos.\n"
        "5. No pegues tablas en texto plano dentro de los campos editables.\n"
        "6. No copies listas largas de evidencia dentro del texto; esa evidencia ya va en tablas.\n"
        "7. Explica que curl define el cumplimiento principal de cabeceras.\n"
        "8. Explica que hsecscan es una capa complementaria de contraste cuando corresponda.\n"
        "9. Explica que cabeceras históricas u obsoletas reportadas por hsecscan no penalizan el cumplimiento principal.\n"
        "10. Si no hay hallazgos XSS, dilo con cautela: no se observaron hallazgos válidos en esta ejecución.\n"
        "11. Si hay cookies, menciona atributos Secure, HttpOnly y SameSite cuando aplique.\n"
        "12. Si hay evidencia XSS, redacta interpretación prudente e indica que requiere validación manual.\n"
        "13. Mantén las secciones aptas para un informe académico/profesional.\n"
        "14. Devuelve únicamente JSON válido, sin markdown, sin comentarios y sin texto adicional.\n\n"
        "Estructura conceptual esperada:\n"
        "- Resumen ejecutivo: síntesis general de la evaluación.\n"
        "- Alcance: URL, enfoque de caja negra y capas incluidas.\n"
        "- Metodología: flujo DASTXH, herramientas y asistencia IA.\n"
        "- Cabeceras: interpretación consolidada de curl + hsecscan, sin duplicar evidencia.\n"
        "- Cookies: interpretación de atributos y riesgos, sin duplicar evidencia.\n"
        "- XSS: interpretación de hallazgos o ausencia de hallazgos, sin duplicar evidencia.\n"
        "- Hallazgos priorizados: puntos que requieren atención.\n"
        "- Recomendaciones: acciones generales de mejora.\n"
        "- Limitaciones: alcance, variabilidad, necesidad de revisión manual.\n"
        "- Conclusión: cierre técnico defendible.\n"
        "- Notas del analista: opcional, puede quedar vacío.\n\n"
        "El JSON debe contener exactamente estas claves:\n"
        f"{fields_text}\n\n"
        "Cada valor debe ser texto. No uses listas JSON anidadas. "
        "Si necesitas enumerar, usa texto con viñetas dentro del string."
    )


def _build_user_prompt(context: Dict[str, Any]) -> str:
    """
    Construye el prompt de usuario con contexto técnico resumido.
    """
    context_json = json.dumps(context, ensure_ascii=False, indent=2)

    return (
        "Genera una primera versión editable del Reporte General Profesional de DASTXH "
        "a partir del siguiente contexto técnico resumido.\n\n"
        "Instrucciones específicas:\n"
        "- Redacta el texto editable del reporte.\n"
        "- No insertes tablas en el texto.\n"
        "- No repitas toda la evidencia objetiva dentro de las secciones.\n"
        "- La evidencia objetiva ya será mostrada debajo de cada sección en tablas separadas.\n"
        "- Usa los conteos, porcentajes y resúmenes exactamente como aparecen en el contexto.\n"
        "- Si una sección no tiene evidencia, redacta con prudencia y aclara la limitación.\n\n"
        "Contexto técnico resumido:\n"
        f"{context_json}\n\n"
        "Devuelve únicamente JSON válido con las claves solicitadas."
    )


# ==========================================================
# PARSEO ROBUSTO DE RESPUESTA IA
# ==========================================================

def _extract_json_object(text: str) -> Dict[str, Any]:
    """
    Extrae un objeto JSON desde la respuesta del modelo.

    Se soportan tres escenarios:
    - respuesta JSON pura;
    - respuesta con ```json ... ```;
    - respuesta con texto extra antes/después del JSON.
    """
    raw = str(text or "").strip()

    if not raw:
        raise ValueError("La respuesta IA está vacía.")

    # Caso 1: JSON directo.
    try:
        parsed = json.loads(raw)

        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Caso 2: bloque fenced ```json ... ```.
    fenced_match = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        raw,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if fenced_match:
        fenced_content = fenced_match.group(1).strip()
        parsed = json.loads(fenced_content)

        if isinstance(parsed, dict):
            return parsed

    # Caso 3: buscar desde la primera llave hasta la última.
    first = raw.find("{")
    last = raw.rfind("}")

    if first >= 0 and last > first:
        candidate = raw[first:last + 1]
        parsed = json.loads(candidate)

        if isinstance(parsed, dict):
            return parsed

    raise ValueError("No se pudo extraer un objeto JSON válido desde la respuesta IA.")


def _parse_openai_compatible_response(response_json: Dict[str, Any]) -> str:
    """
    Extrae el contenido textual desde una respuesta OpenAI-compatible.
    """
    choices = response_json.get("choices")

    if not isinstance(choices, list) or not choices:
        raise ValueError("La respuesta IA no contiene choices.")

    first_choice = choices[0]

    if not isinstance(first_choice, dict):
        raise ValueError("La primera opción de respuesta IA no es válida.")

    message = first_choice.get("message")

    if isinstance(message, dict):
        content = message.get("content")

        if content is not None:
            return str(content)

    text = first_choice.get("text")

    if text is not None:
        return str(text)

    raise ValueError("La respuesta IA no contiene message.content ni text.")


def _validate_generated_payload(payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Valida y normaliza el payload generado por IA.
    """
    if not isinstance(payload, dict):
        raise ValueError("El payload generado por IA no es un objeto JSON.")

    normalized = normalize_professional_report_payload(payload)

    # Validación mínima: debe traer al menos algunas secciones con contenido.
    meaningful_fields = [
        "executive_summary",
        "methodology_text",
        "headers_analysis",
        "general_recommendations",
        "conclusion_text",
    ]

    non_empty_count = 0

    for field in meaningful_fields:
        if str(normalized.get(field) or "").strip():
            non_empty_count += 1

    if non_empty_count < 2:
        raise ValueError("La respuesta IA no contiene suficientes secciones útiles.")

    return normalized
# ==========================================================
# LLAMADA AL MODELO
# ==========================================================

def _call_openai_compatible_chat(
    system_prompt: str,
    user_prompt: str,
) -> Dict[str, Any]:
    """
    Ejecuta una llamada HTTP al endpoint OpenAI-compatible local.
    """
    base_url = _get_report_ai_base_url()
    api_key = _get_report_ai_api_key()
    model = _get_report_ai_model()

    request_body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
        "temperature": _get_report_ai_temperature(),
        "max_tokens": _get_report_ai_max_output_tokens(),
        "stream": False,
    }

    raw_body = json.dumps(request_body, ensure_ascii=False).encode("utf-8")

    request = urllib.request.Request(
        url=_chat_completions_url(base_url),
        data=raw_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=_get_report_ai_timeout_seconds(),
        ) as response:
            response_text = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Error HTTP llamando IA de reporte general: {exc.code}. Respuesta: {error_body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Error de conexión llamando IA de reporte general: {exc}"
        ) from exc

    try:
        parsed = json.loads(response_text)
    except Exception as exc:
        raise RuntimeError(
            f"La respuesta del endpoint IA no fue JSON válido: {response_text[:800]}"
        ) from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("La respuesta del endpoint IA no fue un objeto JSON.")

    return parsed


def _build_debug_context_summary(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye un resumen pequeño del contexto enviado a IA.

    No se usa para persistir todo el prompt.
    Sirve para devolver información diagnóstica controlada.
    """
    execution = context.get("execution") or {}
    headers = context.get("headers") or {}
    cookies = context.get("cookies") or {}
    xss = context.get("xss") or {}

    return {
        "execution_id": execution.get("id"),
        "target_url": execution.get("target_url"),
        "headers_evidence_count": headers.get("evidence_count"),
        "cookies_evidence_count": cookies.get("evidence_count"),
        "xss_evidence_count": xss.get("evidence_count"),
        "headers_compliance": headers.get("cumplimiento_pct"),
        "cookies_count": cookies.get("cookies_count"),
        "xss_display_count": xss.get("xss_display_count"),
    }
# ==========================================================
# API PÚBLICA DEL SERVICIO
# ==========================================================

def generate_professional_report_with_ai(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Genera un reporte general profesional usando IA local.

    Retorna:
    {
      "ok": bool,
      "used_ai": bool,
      "model_name": str | None,
      "payload": dict,
      "fallback_used": bool,
      "error": str | None,
      "context": dict
    }

    Si la IA falla, retorna ok=True con fallback_used=True.
    Esto permite que el usuario siempre obtenga un borrador editable.

    Importante:
    - El payload contiene solo texto editable.
    - La evidencia objetiva no se guarda en el payload.
    - Las tablas se reconstruyen desde detail al abrir la vista o generar PDF.
    """
    fallback_payload = build_deterministic_professional_report_payload(detail)
    context = build_professional_report_ai_context(detail)

    if not _is_report_ai_enabled():
        return {
            "ok": True,
            "used_ai": False,
            "model_name": None,
            "payload": fallback_payload,
            "fallback_used": True,
            "error": "La generación IA del reporte general está desactivada.",
            "context": _build_debug_context_summary(context),
        }

    model_name = _get_report_ai_model()

    try:
        system_prompt = _build_system_prompt()
        user_prompt = _build_user_prompt(context)

        response_json = _call_openai_compatible_chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        content = _parse_openai_compatible_response(response_json)
        generated_json = _extract_json_object(content)
        generated_payload = _validate_generated_payload(generated_json)

        final_payload = merge_generated_payload_with_fallback(
            generated_payload=generated_payload,
            fallback_payload=fallback_payload,
        )

        return {
            "ok": True,
            "used_ai": True,
            "model_name": model_name,
            "payload": final_payload,
            "fallback_used": False,
            "error": None,
            "context": _build_debug_context_summary(context),
        }

    except Exception as exc:
        return {
            "ok": True,
            "used_ai": False,
            "model_name": model_name,
            "payload": fallback_payload,
            "fallback_used": True,
            "error": str(exc),
            "context": _build_debug_context_summary(context),
        }


def build_professional_report_without_ai(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Genera un reporte profesional determinístico sin IA.

    Se usa cuando:
    - el usuario no quiere IA;
    - el modelo local no está disponible;
    - se requiere un fallback estable.

    Importante:
    - El payload contiene solo texto editable.
    - La evidencia objetiva se carga por separado desde professional_report_service.py.
    """
    payload = build_deterministic_professional_report_payload(detail)
    context = build_professional_report_ai_context(detail)

    return {
        "ok": True,
        "used_ai": False,
        "model_name": None,
        "payload": payload,
        "fallback_used": True,
        "error": None,
        "context": _build_debug_context_summary(context),
    }