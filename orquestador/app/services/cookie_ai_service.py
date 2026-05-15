"""
cookie_ai_service.py

Servicio de análisis e interpretación de cookies para DASTXH.

Objetivo:
- Tomar cookies observadas desde cookie_checks.
- Aplicar reglas determinísticas para:
  * clasificar riesgo: alta, media, baja, informativa
  * asociar CWE relacionados
  * detectar si la cookie parece sensible, funcional o de preferencia
- Usar IA local únicamente para redactar:
  * interpretación_humana
  * recommended_action

Reglas importantes:
- La IA NO decide el riesgo desde cero.
- La IA NO inventa evidencia.
- La IA redacta en español latino a partir de evidencia ya calculada.
- Si la IA falla, se usa un fallback determinístico.
- El escaneo nunca debe fallar por problemas de IA.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ==========================================================
# CONFIGURACIÓN
# ==========================================================

@dataclass
class CookieAiConfig:
    """
    Configuración del servicio IA para interpretación de cookies.
    """
    enabled: bool
    base_url: str
    model_name: str
    api_key: Optional[str]
    timeout_seconds: int
    temperature: float
    max_output_tokens: int
    batch_size: int
    max_items: int


def _env_bool(names: List[str], default: bool) -> bool:
    """
    Lee una variable booleana desde varias opciones de nombre.
    """
    for name in names:
        value = os.getenv(name)

        if value is None:
            continue

        normalized = value.strip().lower()

        if normalized in ("true", "1", "yes", "y", "on", "si", "sí"):
            return True

        if normalized in ("false", "0", "no", "n", "off"):
            return False

    return default


def _env_int(names: List[str], default: int, min_value: int, max_value: int) -> int:
    """
    Lee un entero desde variables de entorno y lo limita a un rango seguro.
    """
    for name in names:
        value = os.getenv(name)

        if value is None:
            continue

        try:
            parsed = int(value.strip())
        except Exception:
            continue

        return max(min_value, min(max_value, parsed))

    return default


def _env_float(names: List[str], default: float, min_value: float, max_value: float) -> float:
    """
    Lee un decimal desde variables de entorno y lo limita a un rango seguro.
    """
    for name in names:
        value = os.getenv(name)

        if value is None:
            continue

        try:
            parsed = float(value.strip())
        except Exception:
            continue

        return max(min_value, min(max_value, parsed))

    return default


def _read_config() -> CookieAiConfig:
    """
    Construye la configuración del servicio.

    Variables recomendadas:
    - DASTXH_COOKIE_AI_ENABLED
    - DASTXH_COOKIE_AI_BASE_URL
    - DASTXH_COOKIE_AI_MODEL
    - DASTXH_COOKIE_AI_API_KEY

    También reutiliza variables genéricas DASTXH_AI_* si no existen
    variables específicas para cookies.
    """
    enabled = _env_bool(
        [
            "DASTXH_COOKIE_AI_ENABLED",
            "DASTXH_AI_ENABLED",
        ],
        default=True,
    )

    base_url = (
        os.getenv("DASTXH_COOKIE_AI_BASE_URL")
        or os.getenv("DASTXH_AI_BASE_URL")
        or "http://model-runner.docker.internal:12434/engines/v1"
    ).strip()

    model_name = (
        os.getenv("DASTXH_COOKIE_AI_MODEL")
        or os.getenv("DASTXH_AI_MODEL")
        or "ai/llama3.2"
    ).strip()

    api_key = (
        os.getenv("DASTXH_COOKIE_AI_API_KEY")
        or os.getenv("DASTXH_AI_API_KEY")
        or None
    )

    timeout_seconds = _env_int(
        [
            "DASTXH_COOKIE_AI_TIMEOUT_SECONDS",
            "DASTXH_AI_TIMEOUT_SECONDS",
        ],
        default=240,
        min_value=10,
        max_value=900,
    )

    temperature = _env_float(
        [
            "DASTXH_COOKIE_AI_TEMPERATURE",
            "DASTXH_AI_TEMPERATURE",
        ],
        default=0.1,
        min_value=0.0,
        max_value=0.5,
    )

    max_output_tokens = _env_int(
        [
            "DASTXH_COOKIE_AI_MAX_OUTPUT_TOKENS",
            "DASTXH_AI_MAX_OUTPUT_TOKENS",
            "DASTXH_AI_MAX_TOKENS",
        ],
        default=1800,
        min_value=400,
        max_value=5000,
    )

    batch_size = _env_int(
        [
            "DASTXH_COOKIE_AI_BATCH_SIZE",
        ],
        default=3,
        min_value=1,
        max_value=5,
    )

    max_items = _env_int(
        [
            "DASTXH_COOKIE_AI_MAX_ITEMS",
        ],
        default=80,
        min_value=1,
        max_value=300,
    )

    return CookieAiConfig(
        enabled=enabled,
        base_url=base_url,
        model_name=model_name,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        batch_size=batch_size,
        max_items=max_items,
    )


# ==========================================================
# HELPERS DE TEXTO
# ==========================================================

def _clean_text(value: Any) -> str:
    """
    Limpia texto para comparaciones y prompts.
    """
    text = str(value or "").strip()
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def _nullable_text(value: Any) -> Optional[str]:
    """
    Normaliza valores de texto devueltos por IA.
    """
    if value is None:
        return None

    text = _clean_text(value)

    if text.lower() in ("", "-", "none", "null", "n/a", "na"):
        return None

    return text


def _chunk_items(items: List[Dict[str, Any]], batch_size: int) -> List[List[Dict[str, Any]]]:
    """
    Divide elementos en lotes pequeños.
    """
    if batch_size <= 0:
        batch_size = 1

    chunks: List[List[Dict[str, Any]]] = []

    for index in range(0, len(items), batch_size):
        chunks.append(items[index:index + batch_size])

    return chunks


def _normalize_cookie_name(item: Dict[str, Any]) -> str:
    """
    Devuelve el nombre más útil de la cookie.
    """
    name = _clean_text(item.get("cookie_name"))

    if name:
        return name

    raw = _clean_text(item.get("cookie_raw"))

    if "=" in raw:
        return raw.split("=", 1)[0].strip()

    return raw or "cookie_sin_nombre"
# ==========================================================
# REGLAS DETERMINÍSTICAS OWASP + CWE
# ==========================================================

SENSITIVE_COOKIE_KEYWORDS = (
    "session",
    "sess",
    "sid",
    "ssid",
    "token",
    "auth",
    "jwt",
    "csrf",
    "xsrf",
    "bearer",
    "access",
    "refresh",
    "remember",
    "login",
    "credential",
    "identity",
)

FUNCTIONAL_COOKIE_KEYWORDS = (
    "cart",
    "basket",
    "checkout",
    "order",
    "user_id",
    "userid",
    "account",
    "customer",
    "client",
    "profile",
)

PREFERENCE_COOKIE_KEYWORDS = (
    "theme",
    "prefs",
    "pref",
    "lang",
    "locale",
    "currency",
    "timezone",
    "tz",
    "mode",
    "color",
    "ui",
)


def _contains_any_keyword(text: str, keywords: tuple[str, ...]) -> bool:
    """
    Verifica si el texto contiene alguna palabra clave.
    """
    normalized = text.lower()

    return any(keyword in normalized for keyword in keywords)


def _cookie_kind(cookie_name: str) -> str:
    """
    Clasifica la cookie por nombre probable.

    Resultado:
    - sensible_probable
    - funcional_probable
    - preferencia_probable
    - generica
    """
    name = cookie_name.lower()

    if _contains_any_keyword(name, SENSITIVE_COOKIE_KEYWORDS):
        return "sensible_probable"

    if _contains_any_keyword(name, FUNCTIONAL_COOKIE_KEYWORDS):
        return "funcional_probable"

    if _contains_any_keyword(name, PREFERENCE_COOKIE_KEYWORDS):
        return "preferencia_probable"

    return "generica"


def _same_site_value_normalized(value: Any) -> Optional[str]:
    """
    Normaliza el valor SameSite.
    """
    text = _clean_text(value).lower()

    if not text:
        return None

    return text


def _build_cwe_mappings(
    secure: bool,
    httponly: bool,
    samesite_present: bool,
    samesite_value: Optional[str],
) -> List[Dict[str, str]]:
    """
    Construye el mapeo CWE asociado a atributos de cookie.

    Nota:
    Las CWE se usan como referencia técnica de debilidad.
    Su severidad real depende del contexto de la cookie.
    """
    mappings: List[Dict[str, str]] = []

    if not httponly:
        mappings.append(
            {
                "cwe_id": "CWE-1004",
                "name": "Sensitive Cookie Without 'HttpOnly' Flag",
                "reason": "La cookie no declara HttpOnly. Si contiene datos sensibles, podría ser accesible mediante JavaScript del navegador.",
            }
        )

    if not secure:
        mappings.append(
            {
                "cwe_id": "CWE-614",
                "name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
                "reason": "La cookie no declara Secure. Si el sitio o alguna ruta usa HTTP, podría exponerse fuera de un canal cifrado.",
            }
        )

    same_site_none_without_secure = (
        samesite_present
        and samesite_value == "none"
        and not secure
    )

    if not samesite_present or same_site_none_without_secure:
        mappings.append(
            {
                "cwe_id": "CWE-1275",
                "name": "Sensitive Cookie with Improper SameSite Attribute",
                "reason": "La cookie no declara SameSite o usa SameSite=None sin Secure, lo cual puede aumentar exposición en solicitudes cross-site.",
            }
        )

    return mappings


def _infer_cookie_risk(
    cookie_kind: str,
    secure: bool,
    httponly: bool,
    samesite_present: bool,
    samesite_value: Optional[str],
) -> str:
    """
    Clasifica riesgo de cookie con reglas internas DASTXH.

    Reglas base:
    - alta:
      cookie sensible probable y falta HttpOnly o Secure,
      o SameSite=None sin Secure.
    - media:
      cookie funcional con atributos faltantes.
    - baja:
      cookie de preferencia con atributos faltantes.
    - informativa:
      sin señales claras o atributos razonables.
    """
    missing_secure = not secure
    missing_httponly = not httponly
    missing_samesite = not samesite_present
    same_site_none_without_secure = (
        samesite_present
        and samesite_value == "none"
        and not secure
    )

    has_any_missing_attribute = (
        missing_secure
        or missing_httponly
        or missing_samesite
        or same_site_none_without_secure
    )

    if same_site_none_without_secure:
        return "alta"

    if cookie_kind == "sensible_probable" and (missing_httponly or missing_secure):
        return "alta"

    if cookie_kind == "funcional_probable" and has_any_missing_attribute:
        return "media"

    if cookie_kind == "preferencia_probable" and has_any_missing_attribute:
        return "baja"

    if has_any_missing_attribute:
        return "media"

    return "informativa"


def _build_rule_notes(
    cookie_kind: str,
    secure: bool,
    httponly: bool,
    samesite_present: bool,
    samesite_value: Optional[str],
) -> List[str]:
    """
    Construye notas explicativas de reglas.
    """
    notes: List[str] = []

    if cookie_kind == "sensible_probable":
        notes.append("El nombre de la cookie sugiere posible relación con sesión, autenticación o token.")

    elif cookie_kind == "funcional_probable":
        notes.append("El nombre de la cookie sugiere uso funcional dentro del flujo del usuario.")

    elif cookie_kind == "preferencia_probable":
        notes.append("El nombre de la cookie sugiere uso de preferencia o personalización.")

    else:
        notes.append("No se identificó una señal clara de sensibilidad a partir del nombre.")

    if not secure:
        notes.append("La cookie no declara Secure.")

    if not httponly:
        notes.append("La cookie no declara HttpOnly.")

    if not samesite_present:
        notes.append("La cookie no declara SameSite.")
    elif samesite_value == "none" and not secure:
        notes.append("La cookie usa SameSite=None sin Secure.")

    if secure and httponly and samesite_present:
        notes.append("La cookie declara los atributos principales de endurecimiento evaluados.")

    return notes


def _build_deterministic_interpretation(
    cookie_name: str,
    cookie_kind: str,
    risk_level: str,
    secure: bool,
    httponly: bool,
    samesite_present: bool,
    samesite_value: Optional[str],
) -> str:
    """
    Genera una interpretación base sin IA.

    Se usa como fallback cuando el modelo no responde correctamente.
    """
    missing: List[str] = []

    if not secure:
        missing.append("Secure")

    if not httponly:
        missing.append("HttpOnly")

    if not samesite_present:
        missing.append("SameSite")

    if samesite_present and samesite_value == "none" and not secure:
        missing.append("combinación SameSite=None sin Secure")

    if not missing:
        return (
            f"La cookie {cookie_name} declara los atributos principales evaluados. "
            "No se identifican debilidades relevantes en los atributos revisados."
        )

    if cookie_kind == "sensible_probable":
        context = "El nombre sugiere que podría estar relacionada con sesión, autenticación o tokens."
    elif cookie_kind == "funcional_probable":
        context = "El nombre sugiere que podría estar relacionada con una función del usuario dentro del sitio."
    elif cookie_kind == "preferencia_probable":
        context = "El nombre sugiere que podría corresponder a preferencias o personalización."
    else:
        context = "No se confirma sensibilidad por nombre, pero faltan atributos de endurecimiento."

    return (
        f"La cookie {cookie_name} no declara {', '.join(missing)}. "
        f"{context} El riesgo se clasifica como {risk_level} de forma orientativa, "
        "según reglas internas alineadas con OWASP y mapeo CWE."
    )


def _build_deterministic_recommendation(
    cookie_kind: str,
    secure: bool,
    httponly: bool,
    samesite_present: bool,
    samesite_value: Optional[str],
) -> str:
    """
    Genera una recomendación base sin IA.
    """
    recommendations: List[str] = []

    if not secure:
        recommendations.append("Configurar Secure cuando la cookie deba viajar únicamente sobre HTTPS")

    if not httponly:
        if cookie_kind == "preferencia_probable":
            recommendations.append(
                "Evaluar si HttpOnly aplica; si JavaScript necesita leer la preferencia, documentar la excepción"
            )
        else:
            recommendations.append("Configurar HttpOnly si la cookie no necesita ser leída por JavaScript")

    if not samesite_present:
        recommendations.append("Definir SameSite=Lax o SameSite=Strict según el flujo del sitio")

    if samesite_present and samesite_value == "none" and not secure:
        recommendations.append("Si se requiere SameSite=None, también debe configurarse Secure")

    if not recommendations:
        return "Mantener la configuración actual y verificar que no se almacenen datos sensibles innecesarios en la cookie."

    return ". ".join(recommendations) + "."


def _analyze_cookie_with_rules(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aplica reglas determinísticas a una cookie.
    """
    cookie_check_id = int(item.get("id") or item.get("cookie_check_id") or 0)
    cookie_name = _normalize_cookie_name(item)
    cookie_raw = _clean_text(item.get("cookie_raw"))

    secure = bool(item.get("secure"))
    httponly = bool(item.get("httponly"))
    samesite_present = bool(item.get("samesite_present"))
    samesite_value = _same_site_value_normalized(item.get("samesite_value"))

    cookie_kind = _cookie_kind(cookie_name)

    risk_level = _infer_cookie_risk(
        cookie_kind=cookie_kind,
        secure=secure,
        httponly=httponly,
        samesite_present=samesite_present,
        samesite_value=samesite_value,
    )

    cwe_mappings = _build_cwe_mappings(
        secure=secure,
        httponly=httponly,
        samesite_present=samesite_present,
        samesite_value=samesite_value,
    )

    rule_notes = _build_rule_notes(
        cookie_kind=cookie_kind,
        secure=secure,
        httponly=httponly,
        samesite_present=samesite_present,
        samesite_value=samesite_value,
    )

    fallback_interpretation = _build_deterministic_interpretation(
        cookie_name=cookie_name,
        cookie_kind=cookie_kind,
        risk_level=risk_level,
        secure=secure,
        httponly=httponly,
        samesite_present=samesite_present,
        samesite_value=samesite_value,
    )

    fallback_recommendation = _build_deterministic_recommendation(
        cookie_kind=cookie_kind,
        secure=secure,
        httponly=httponly,
        samesite_present=samesite_present,
        samesite_value=samesite_value,
    )

    return {
        "cookie_check_id": cookie_check_id,
        "cookie_name": cookie_name,
        "cookie_raw": cookie_raw,
        "cookie_kind": cookie_kind,
        "secure": secure,
        "httponly": httponly,
        "samesite_present": samesite_present,
        "samesite_value": samesite_value,
        "risk_level": risk_level,
        "cwe_mappings": cwe_mappings,
        "rule_notes": rule_notes,
        "interpretation_humana": fallback_interpretation,
        "recommended_action": fallback_recommendation,
        "model_name": "rules",
    }
# ==========================================================
# PROMPT Y CLIENTE IA
# ==========================================================

def _build_system_prompt() -> str:
    """
    Prompt de sistema para limitar el uso de IA.

    La IA no clasifica desde cero: solo redacta con base en reglas dadas.
    """
    return (
        "Eres un asistente técnico de ciberseguridad web. "
        "Tu tarea es redactar en español latino una interpretación breve y una recomendación breve "
        "sobre cookies HTTP. "
        "No cambies el nivel de riesgo proporcionado. "
        "No inventes evidencia. "
        "No agregues CWE no proporcionados. "
        "No digas que una cookie es de sesión si solo se indicó como probable. "
        "Responde únicamente JSON válido, sin Markdown y sin texto adicional."
    )


def _build_user_prompt(items: List[Dict[str, Any]]) -> str:
    """
    Construye prompt compacto para el modelo.
    """
    payload = {
        "tarea": "redactar_interpretacion_cookie",
        "reglas": [
            "Usa el risk_level proporcionado sin modificarlo.",
            "Usa los cwe_mappings proporcionados sin agregar nuevos.",
            "La interpretación debe tener máximo 2 oraciones.",
            "La recomendación debe tener máximo 2 oraciones.",
            "No inventes datos sensibles.",
            "No uses formato Markdown.",
        ],
        "formato_respuesta": {
            "cookies": [
                {
                    "cookie_check_id": 1,
                    "interpretation_humana": "texto breve",
                    "recommended_action": "texto breve",
                }
            ]
        },
        "items": [
            {
                "cookie_check_id": item["cookie_check_id"],
                "cookie_name": item["cookie_name"],
                "cookie_kind": item["cookie_kind"],
                "secure": item["secure"],
                "httponly": item["httponly"],
                "samesite_present": item["samesite_present"],
                "samesite_value": item["samesite_value"],
                "risk_level": item["risk_level"],
                "cwe_mappings": item["cwe_mappings"],
                "rule_notes": item["rule_notes"],
            }
            for item in items
        ],
    }

    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _chat_completions_url(base_url: str) -> str:
    """
    Construye la URL del endpoint compatible con OpenAI Chat Completions.
    """
    clean = str(base_url or "").strip().rstrip("/")

    if clean.endswith("/chat/completions"):
        return clean

    return f"{clean}/chat/completions"


def _build_request_body(
    items: List[Dict[str, Any]],
    config: CookieAiConfig,
) -> Dict[str, Any]:
    """
    Construye request compatible con OpenAI Chat Completions.
    """
    return {
        "model": config.model_name,
        "temperature": config.temperature,
        "max_tokens": config.max_output_tokens,
        "messages": [
            {
                "role": "system",
                "content": _build_system_prompt(),
            },
            {
                "role": "user",
                "content": _build_user_prompt(items),
            },
        ],
    }


def _extract_chat_content(response_json: Dict[str, Any]) -> str:
    """
    Extrae choices[0].message.content desde una respuesta compatible.
    """
    choices = response_json.get("choices")

    if not isinstance(choices, list) or not choices:
        return ""

    first = choices[0]

    if not isinstance(first, dict):
        return ""

    message = first.get("message")

    if isinstance(message, dict):
        content = message.get("content")

        if content is not None:
            return str(content)

    text = first.get("text")

    if text is not None:
        return str(text)

    return ""


def _call_model_runner(
    items: List[Dict[str, Any]],
    config: CookieAiConfig,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Llama al modelo local compatible con OpenAI.
    """
    url = _chat_completions_url(config.base_url)
    body = _build_request_body(items, config)
    raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"

    request = urllib.request.Request(
        url=url,
        data=raw_body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            raw_response = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = ""

        return None, f"HTTP {exc.code}: {error_body[:800]}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    try:
        parsed = json.loads(raw_response)
    except Exception:
        return None, f"Respuesta IA no es JSON de API válido: {raw_response[:800]}"

    content = _extract_chat_content(parsed)

    if not content:
        return None, "Respuesta IA sin contenido."

    return content, None


# ==========================================================
# PARSEO DE RESPUESTA IA
# ==========================================================

def _strip_code_fences(text: str) -> str:
    """
    Elimina fences Markdown si el modelo los devuelve por error.
    """
    cleaned = str(text or "").strip()

    if cleaned.startswith("```"):
        lines = cleaned.splitlines()

        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]

        cleaned = "\n".join(lines).strip()

    return cleaned


def _extract_json_object_text(text: str) -> str:
    """
    Extrae el primer objeto JSON de la respuesta.
    """
    cleaned = _strip_code_fences(text)

    if cleaned.startswith("{") and cleaned.endswith("}"):
        return cleaned

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start >= 0 and end > start:
        return cleaned[start:end + 1]

    return cleaned


def _parse_ai_response(content: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Convierte respuesta IA a lista de interpretaciones.

    Formato esperado:
    {
      "cookies": [
        {
          "cookie_check_id": 1,
          "interpretation_humana": "...",
          "recommended_action": "..."
        }
      ]
    }
    """
    json_text = _extract_json_object_text(content)

    try:
        parsed = json.loads(json_text)
    except Exception as exc:
        return [], f"No se pudo parsear JSON de cookies: {exc}. Respuesta: {content[:800]}"

    if not isinstance(parsed, dict):
        return [], "La respuesta IA no es un objeto JSON."

    cookies = parsed.get("cookies")

    if not isinstance(cookies, list):
        return [], "La respuesta IA no contiene lista 'cookies'."

    result: List[Dict[str, Any]] = []

    for item in cookies:
        if not isinstance(item, dict):
            continue

        try:
            cookie_check_id = int(item.get("cookie_check_id") or item.get("id") or 0)
        except Exception:
            continue

        if cookie_check_id <= 0:
            continue

        interpretation = _nullable_text(item.get("interpretation_humana"))
        recommendation = _nullable_text(item.get("recommended_action"))

        if not interpretation and not recommendation:
            continue

        result.append(
            {
                "cookie_check_id": cookie_check_id,
                "interpretation_humana": interpretation,
                "recommended_action": recommendation,
            }
        )

    return result, None


def _merge_ai_text_into_rule_results(
    rule_results: List[Dict[str, Any]],
    ai_results: List[Dict[str, Any]],
    model_name: str,
) -> List[Dict[str, Any]]:
    """
    Inserta interpretación/recomendación IA sobre el resultado por reglas.

    El riesgo y CWE se mantienen desde reglas, no desde IA.
    """
    ai_by_id: Dict[int, Dict[str, Any]] = {}

    for item in ai_results:
        try:
            cookie_check_id = int(item.get("cookie_check_id"))
        except Exception:
            continue

        ai_by_id[cookie_check_id] = item

    merged: List[Dict[str, Any]] = []

    for rule_item in rule_results:
        current = dict(rule_item)
        cookie_check_id = int(current.get("cookie_check_id") or 0)
        ai_item = ai_by_id.get(cookie_check_id)

        if ai_item:
            current["interpretation_humana"] = (
                ai_item.get("interpretation_humana")
                or current.get("interpretation_humana")
            )
            current["recommended_action"] = (
                ai_item.get("recommended_action")
                or current.get("recommended_action")
            )
            current["model_name"] = model_name

        merged.append(current)

    return merged
# ==========================================================
# TRADUCCIÓN / INTERPRETACIÓN POR LOTES
# ==========================================================

def _interpret_batch_once(
    batch: List[Dict[str, Any]],
    config: CookieAiConfig,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Intenta obtener interpretación IA para un lote.
    """
    content, call_error = _call_model_runner(batch, config)

    if call_error:
        return [], call_error

    parsed, parse_error = _parse_ai_response(content or "")

    if parse_error:
        return [], parse_error

    if not parsed:
        return [], "La respuesta IA fue válida, pero no produjo interpretaciones útiles."

    return parsed, None


def _interpret_with_ai(
    rule_results: List[Dict[str, Any]],
    config: CookieAiConfig,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Intenta enriquecer los resultados por reglas usando IA.
    """
    meta: Dict[str, Any] = {
        "enabled": config.enabled,
        "model_name": config.model_name,
        "base_url": config.base_url,
        "requested_cookies": len(rule_results),
        "interpreted_by_ai": 0,
        "batches_count": 0,
        "batch_size_effective": config.batch_size,
        "errors": [],
    }

    if not config.enabled:
        meta["skipped_reason"] = "cookie_ai_disabled"
        return rule_results, meta

    batches = _chunk_items(rule_results, config.batch_size)
    meta["batches_count"] = len(batches)

    all_ai_results: List[Dict[str, Any]] = []

    for batch_index, batch in enumerate(batches, start=1):
        ai_results, error = _interpret_batch_once(batch, config)

        if error:
            meta["errors"].append(
                {
                    "batch_index": batch_index,
                    "items": len(batch),
                    "error": error,
                }
            )

            # Fallback individual cuando el lote falla.
            if len(batch) > 1:
                for item in batch:
                    single_results, single_error = _interpret_batch_once([item], config)

                    if single_error:
                        meta["errors"].append(
                            {
                                "batch_index": batch_index,
                                "items": 1,
                                "cookie_check_id": item.get("cookie_check_id"),
                                "error": single_error,
                            }
                        )
                        continue

                    all_ai_results.extend(single_results)

            continue

        all_ai_results.extend(ai_results)

    merged = _merge_ai_text_into_rule_results(
        rule_results=rule_results,
        ai_results=all_ai_results,
        model_name=config.model_name,
    )

    interpreted_ids = {
        int(item.get("cookie_check_id"))
        for item in all_ai_results
        if item.get("cookie_check_id")
    }

    meta["interpreted_by_ai"] = len(interpreted_ids)
    meta["ok"] = bool(interpreted_ids) and not bool(meta["errors"])
    meta["partial_success"] = bool(interpreted_ids) and bool(meta["errors"])

    return merged, meta


# ==========================================================
# API PÚBLICA DEL SERVICIO
# ==========================================================

def interpret_cookie_checks_with_ai(
    cookies: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Analiza cookies usando reglas + IA.

    Parámetros:
    - cookies: filas devueltas por db.list_cookie_checks_for_interpretation(...)

    Devuelve:
    - interpretations: lista lista para db.update_cookie_check_interpretations(...)
    - meta: resumen para run_meta.json

    Este método nunca debe romper el escaneo.
    Si la IA falla, se devuelven resultados por reglas.
    """
    config = _read_config()
    started = time.time()

    meta: Dict[str, Any] = {
        "enabled": config.enabled,
        "model_name": config.model_name,
        "base_url": config.base_url,
        "requested_cookies": len(cookies or []),
        "candidate_cookies": 0,
        "interpreted_cookies": 0,
        "interpreted_by_ai": 0,
        "rules_fallback_used": False,
        "errors": [],
        "started_at_epoch": started,
        "finished_at_epoch": None,
    }

    if not cookies:
        meta["finished_at_epoch"] = time.time()
        meta["skipped_reason"] = "no_cookie_checks"
        return [], meta

    rule_results: List[Dict[str, Any]] = []

    for raw_item in cookies[:config.max_items]:
        try:
            analyzed = _analyze_cookie_with_rules(raw_item)
        except Exception as exc:
            meta["errors"].append(
                {
                    "cookie_check_id": raw_item.get("id"),
                    "error": f"No fue posible analizar cookie por reglas: {exc}",
                }
            )
            continue

        if analyzed.get("cookie_check_id"):
            rule_results.append(analyzed)

    meta["candidate_cookies"] = len(rule_results)

    if not rule_results:
        meta["finished_at_epoch"] = time.time()
        meta["skipped_reason"] = "no_valid_cookie_checks"
        return [], meta

    # Primero tenemos resultados por reglas.
    # Luego intentamos mejorar redacción con IA.
    enriched_results, ai_meta = _interpret_with_ai(
        rule_results=rule_results,
        config=config,
    )

    meta["interpreted_by_ai"] = int(ai_meta.get("interpreted_by_ai", 0) or 0)
    meta["ai"] = ai_meta

    if meta["interpreted_by_ai"] <= 0:
        meta["rules_fallback_used"] = True

    final_results: List[Dict[str, Any]] = []

    for item in enriched_results:
        final_results.append(
            {
                "cookie_check_id": item.get("cookie_check_id"),
                "risk_level": item.get("risk_level"),
                "cwe_mappings": item.get("cwe_mappings"),
                "interpretation_humana": item.get("interpretation_humana"),
                "recommended_action": item.get("recommended_action"),
                "model_name": item.get("model_name"),
            }
        )

    meta["interpreted_cookies"] = len(final_results)
    meta["finished_at_epoch"] = time.time()
    meta["ok"] = len(final_results) > 0

    return final_results, meta


def is_cookie_ai_enabled() -> bool:
    """
    Permite consultar si la interpretación IA de cookies está activa.
    """
    return _read_config().enabled