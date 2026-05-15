"""
hsecscan_ai_translation_service.py

Servicio de traducción IA para resultados de hsecscan.

Objetivo:
- Traducir al español latino únicamente campos técnicos generados por hsecscan:
  * security_description  -> security_description_es
  * recommendations       -> recommendations_es
  * cwe                   -> cwe_es

Reglas importantes:
- No reemplaza la evidencia original en inglés.
- No interpreta hallazgos.
- No inventa recomendaciones nuevas.
- Solo mejora la legibilidad para la GUI.
- Si la IA falla, el escaneo no debe fallar.

Corrección de esta versión:
- El prompt anterior enviaba un objeto con task/rules/output_schema/items.
  El modelo local estaba traduciendo ese objeto completo en vez de responder
  solamente con la lista "translations".
- Esta versión usa un prompt más directo y simple:
  * instrucciones en texto
  * entrada mínima por check
  * salida JSON estricta
- También acepta dos formatos válidos:
  * {"translations": [...]}
  * {"check_id": ..., "security_description_es": ..., ...}
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
class HsecscanAiTranslationConfig:
    """
    Configuración del servicio de traducción IA.

    Se carga desde variables de entorno para evitar valores rígidos en código.
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
    max_chars_per_field: int


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
    Lee un float desde variables de entorno y lo limita a un rango seguro.
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


def _read_config() -> HsecscanAiTranslationConfig:
    """
    Construye la configuración del servicio.

    Para el modelo local llama3.2 se recomienda:
    - batch_size bajo
    - temperatura baja
    - campos recortados
    """
    enabled = _env_bool(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_ENABLED",
            "DASTXH_HSECSCAN_TRANSLATION_ENABLED",
            "DASTXH_AI_ENABLED",
        ],
        default=True,
    )

    base_url = (
        os.getenv("DASTXH_HSECSCAN_AI_TRANSLATION_BASE_URL")
        or os.getenv("DASTXH_AI_BASE_URL")
        or os.getenv("XSS_AI_BASE_URL")
        or "http://model-runner.docker.internal:12434/engines/v1"
    ).strip()

    model_name = (
        os.getenv("DASTXH_HSECSCAN_AI_TRANSLATION_MODEL")
        or os.getenv("DASTXH_AI_MODEL")
        or os.getenv("XSS_AI_MODEL")
        or "ai/llama3.2"
    ).strip()

    api_key = (
        os.getenv("DASTXH_HSECSCAN_AI_TRANSLATION_API_KEY")
        or os.getenv("DASTXH_AI_API_KEY")
        or os.getenv("XSS_AI_API_KEY")
        or None
    )

    timeout_seconds = _env_int(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_TIMEOUT_SECONDS",
            "DASTXH_AI_TIMEOUT_SECONDS",
            "XSS_AI_TIMEOUT_SECONDS",
        ],
        default=300,
        min_value=10,
        max_value=900,
    )

    temperature = _env_float(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_TEMPERATURE",
            "DASTXH_AI_TEMPERATURE",
        ],
        default=0.1,
        min_value=0.0,
        max_value=0.5,
    )

    max_output_tokens = _env_int(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_MAX_OUTPUT_TOKENS",
            "DASTXH_AI_MAX_OUTPUT_TOKENS",
            "DASTXH_AI_MAX_TOKENS",
        ],
        default=3000,
        min_value=500,
        max_value=8000,
    )

    batch_size = _env_int(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_BATCH_SIZE",
        ],
        default=1,
        min_value=1,
        max_value=2,
    )

    max_items = _env_int(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_MAX_ITEMS",
        ],
        default=80,
        min_value=1,
        max_value=300,
    )

    max_chars_per_field = _env_int(
        [
            "DASTXH_HSECSCAN_AI_TRANSLATION_MAX_CHARS_PER_FIELD",
        ],
        default=650,
        min_value=100,
        max_value=900,
    )

    return HsecscanAiTranslationConfig(
        enabled=enabled,
        base_url=base_url,
        model_name=model_name,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        batch_size=batch_size,
        max_items=max_items,
        max_chars_per_field=max_chars_per_field,
    )


# ==========================================================
# HELPERS DE TEXTO
# ==========================================================

def _clean_text(value: Any) -> str:
    """
    Limpia texto para enviarlo a la IA.

    No cambia significado; solo compacta espacios y saltos de línea.
    """
    text = str(value or "").strip()
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def _truncate_text(value: Any, max_chars: int) -> Optional[str]:
    """
    Recorta texto demasiado largo para mantener estable la respuesta JSON.
    """
    text = _clean_text(value)

    if not text:
        return None

    if len(text) <= max_chars:
        return text

    return text[:max_chars].rstrip() + "..."


def _has_text(value: Any) -> bool:
    """
    Indica si un campo tiene texto útil.
    """
    return bool(_clean_text(value))


def _nullable_text(value: Any) -> Optional[str]:
    """
    Normaliza campos traducidos.

    Convierte "", "-", "null" y similares en None.
    """
    if value is None:
        return None

    text = _clean_text(value)

    if text.lower() in ("", "-", "none", "null", "n/a", "na"):
        return None

    return text


def _already_translated(item: Dict[str, Any]) -> bool:
    """
    Determina si el check ya tiene traducción suficiente.
    """
    return any(
        _has_text(item.get(field_name))
        for field_name in (
            "security_description_es",
            "recommendations_es",
            "cwe_es",
        )
    )


def _should_translate_check(item: Dict[str, Any]) -> bool:
    """
    Determina si un check de hsecscan merece ser enviado a traducción.
    """
    if _already_translated(item):
        return False

    return any(
        _has_text(item.get(field_name))
        for field_name in (
            "security_description",
            "recommendations",
            "cwe",
        )
    )


def _chunk_items(items: List[Dict[str, Any]], batch_size: int) -> List[List[Dict[str, Any]]]:
    """
    Divide los checks en lotes pequeños.
    """
    if batch_size <= 0:
        batch_size = 1

    chunks: List[List[Dict[str, Any]]] = []

    for index in range(0, len(items), batch_size):
        chunks.append(items[index:index + batch_size])

    return chunks
# ==========================================================
# PROMPT Y PAYLOAD
# ==========================================================

def _build_translation_items(
    checks: List[Dict[str, Any]],
    config: HsecscanAiTranslationConfig,
) -> List[Dict[str, Any]]:
    """
    Prepara los campos mínimos que se enviarán a la IA.
    """
    prepared: List[Dict[str, Any]] = []

    for item in checks:
        raw_id = item.get("id")

        try:
            check_id = int(raw_id)
        except Exception:
            continue

        if check_id <= 0:
            continue

        if not _should_translate_check(item):
            continue

        prepared.append(
            {
                "check_id": check_id,
                "header_name": _truncate_text(item.get("header_name"), 160),
                "record_type": _truncate_text(item.get("record_type"), 40),
                "risk_level": _truncate_text(item.get("risk_level"), 40),
                "security_description": _truncate_text(
                    item.get("security_description"),
                    config.max_chars_per_field,
                ),
                "recommendations": _truncate_text(
                    item.get("recommendations"),
                    config.max_chars_per_field,
                ),
                "cwe": _truncate_text(
                    item.get("cwe"),
                    config.max_chars_per_field,
                ),
            }
        )

    return prepared[:config.max_items]


def _build_system_prompt() -> str:
    """
    Prompt de sistema.

    Se evita pedirle al modelo que traduzca un objeto de instrucciones.
    Solo se le pide generar el JSON final.
    """
    return (
        "Eres un traductor técnico de ciberseguridad web. "
        "Tu única tarea es traducir del inglés al español latino los campos indicados. "
        "No interpretes, no expliques, no agregues recomendaciones y no cambies el sentido técnico. "
        "Conserva nombres de cabeceras HTTP, URLs, comandos, nombres de tecnologías, siglas y códigos CWE. "
        "Devuelve solamente JSON válido. "
        "No uses Markdown. "
        "No agregues texto antes ni después del JSON."
    )


def _build_single_item_prompt(item: Dict[str, Any]) -> str:
    """
    Construye un prompt simple para un solo check.

    Este formato evita que el modelo traduzca un esquema completo.
    """
    return (
        "Traduce al español latino los campos técnicos siguientes.\n"
        "No traduzcas header_name.\n"
        "No traduzcas códigos como CWE-79, CWE-693 o CWE-200.\n"
        "Si un campo de entrada es null, responde null en su traducción.\n"
        "No agregues información nueva.\n\n"
        "Debes responder exactamente con este formato JSON:\n"
        "{\n"
        '  "translations": [\n'
        "    {\n"
        f'      "check_id": {int(item["check_id"])},\n'
        '      "security_description_es": "...",\n'
        '      "recommendations_es": "...",\n'
        '      "cwe_es": "..."\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Entrada:\n"
        f"check_id: {int(item['check_id'])}\n"
        f"header_name: {item.get('header_name') or 'null'}\n"
        f"record_type: {item.get('record_type') or 'null'}\n"
        f"risk_level: {item.get('risk_level') or 'null'}\n"
        f"security_description: {item.get('security_description') or 'null'}\n"
        f"recommendations: {item.get('recommendations') or 'null'}\n"
        f"cwe: {item.get('cwe') or 'null'}\n"
    )


def _build_multi_item_prompt(items: List[Dict[str, Any]]) -> str:
    """
    Construye un prompt simple para más de un check.

    Aunque el batch recomendado es 1, se conserva soporte para 2.
    """
    lines: List[str] = [
        "Traduce al español latino los campos técnicos de cada registro.",
        "No traduzcas header_name.",
        "No traduzcas códigos como CWE-79, CWE-693 o CWE-200.",
        "Si un campo de entrada es null, responde null en su traducción.",
        "No agregues información nueva.",
        "",
        "Responde únicamente este JSON:",
        '{"translations":[{"check_id":1,"security_description_es":"...","recommendations_es":"...","cwe_es":"..."}]}',
        "",
        "Registros:",
    ]

    for item in items:
        lines.extend(
            [
                "",
                f"check_id: {int(item['check_id'])}",
                f"header_name: {item.get('header_name') or 'null'}",
                f"record_type: {item.get('record_type') or 'null'}",
                f"risk_level: {item.get('risk_level') or 'null'}",
                f"security_description: {item.get('security_description') or 'null'}",
                f"recommendations: {item.get('recommendations') or 'null'}",
                f"cwe: {item.get('cwe') or 'null'}",
            ]
        )

    return "\n".join(lines)


def _build_user_prompt(items: List[Dict[str, Any]]) -> str:
    """
    Construye el prompt de usuario.

    Si hay un solo item, se usa un prompt aún más directo.
    """
    if len(items) == 1:
        return _build_single_item_prompt(items[0])

    return _build_multi_item_prompt(items)


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
    config: HsecscanAiTranslationConfig,
) -> Dict[str, Any]:
    """
    Construye el cuerpo para un endpoint compatible con OpenAI.
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


# ==========================================================
# CLIENTE HTTP IA
# ==========================================================

def _extract_chat_content(response_json: Dict[str, Any]) -> str:
    """
    Extrae el contenido textual desde una respuesta compatible con OpenAI.
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
    config: HsecscanAiTranslationConfig,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Ejecuta una llamada al modelo IA.

    Devuelve:
    - content: respuesta textual del modelo
    - error: texto de error si algo falló
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
        return None, "Respuesta IA sin contenido en choices[0].message.content."

    return content, None
# ==========================================================
# PARSEO ROBUSTO DE RESPUESTA IA
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


def _coerce_single_translation_object(parsed: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Permite aceptar una respuesta de este tipo:

    {
      "check_id": 1,
      "security_description_es": "...",
      "recommendations_es": "...",
      "cwe_es": "..."
    }

    y convertirla internamente a lista.
    """
    if "check_id" not in parsed and "id" not in parsed:
        return None

    return [parsed]


def _parse_translation_response(content: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Convierte la respuesta de IA en una lista de traducciones.

    Formatos aceptados:
    1)
    {
      "translations": [
        {
          "check_id": 1,
          "security_description_es": "...",
          "recommendations_es": "...",
          "cwe_es": "..."
        }
      ]
    }

    2)
    {
      "check_id": 1,
      "security_description_es": "...",
      "recommendations_es": "...",
      "cwe_es": "..."
    }
    """
    json_text = _extract_json_object_text(content)

    try:
        parsed = json.loads(json_text)
    except Exception as exc:
        return [], f"No se pudo parsear JSON de traducción: {exc}. Respuesta: {content[:800]}"

    if not isinstance(parsed, dict):
        return [], "La respuesta de traducción no es un objeto JSON."

    translations = parsed.get("translations")

    if translations is None:
        translations = _coerce_single_translation_object(parsed)

    if not isinstance(translations, list):
        return [], "La respuesta no contiene lista 'translations'."

    result: List[Dict[str, Any]] = []

    for item in translations:
        if not isinstance(item, dict):
            continue

        raw_check_id = item.get("check_id", item.get("id"))

        try:
            check_id = int(raw_check_id)
        except Exception:
            continue

        if check_id <= 0:
            continue

        result.append(
            {
                "check_id": check_id,
                "security_description_es": _nullable_text(item.get("security_description_es")),
                "recommendations_es": _nullable_text(item.get("recommendations_es")),
                "cwe_es": _nullable_text(item.get("cwe_es")),
            }
        )

    return result, None


# ==========================================================
# VALIDACIÓN DE TRADUCCIONES
# ==========================================================

def _build_source_index(items: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """
    Crea un índice de checks originales por id.
    """
    result: Dict[int, Dict[str, Any]] = {}

    for item in items:
        try:
            check_id = int(item.get("check_id"))
        except Exception:
            continue

        result[check_id] = item

    return result


def _looks_same_as_source(translated: Any, original: Any) -> bool:
    """
    Detecta si el modelo devolvió exactamente el texto original.

    No bloquea traducciones mixtas con términos técnicos conservados.
    Solo bloquea igualdad textual completa.
    """
    translated_text = _clean_text(translated).lower()
    original_text = _clean_text(original).lower()

    if not translated_text or not original_text:
        return False

    return translated_text == original_text


def _validate_translations_against_source(
    source_items: List[Dict[str, Any]],
    translations: List[Dict[str, Any]],
    model_name: str,
) -> List[Dict[str, Any]]:
    """
    Valida que la IA solo haya traducido campos que existían en el origen.

    Si el campo original venía vacío, no se acepta una traducción inventada.
    Si el modelo devuelve exactamente el texto original, no se guarda ese campo.
    """
    source_index = _build_source_index(source_items)
    valid: List[Dict[str, Any]] = []

    for item in translations:
        try:
            check_id = int(item.get("check_id"))
        except Exception:
            continue

        source = source_index.get(check_id)

        if not source:
            continue

        security_description_es = item.get("security_description_es")
        recommendations_es = item.get("recommendations_es")
        cwe_es = item.get("cwe_es")

        if not _has_text(source.get("security_description")):
            security_description_es = None
        elif _looks_same_as_source(security_description_es, source.get("security_description")):
            security_description_es = None

        if not _has_text(source.get("recommendations")):
            recommendations_es = None
        elif _looks_same_as_source(recommendations_es, source.get("recommendations")):
            recommendations_es = None

        if not _has_text(source.get("cwe")):
            cwe_es = None
        elif _looks_same_as_source(cwe_es, source.get("cwe")):
            cwe_es = None

        if not any(
            _has_text(value)
            for value in (
                security_description_es,
                recommendations_es,
                cwe_es,
            )
        ):
            continue

        valid.append(
            {
                "check_id": check_id,
                "security_description_es": security_description_es,
                "recommendations_es": recommendations_es,
                "cwe_es": cwe_es,
                "translation_model_name": model_name,
            }
        )

    return valid


def _translate_batch_once(
    batch: List[Dict[str, Any]],
    config: HsecscanAiTranslationConfig,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Intenta traducir un lote una sola vez.
    """
    content, call_error = _call_model_runner(batch, config)

    if call_error:
        return [], call_error

    parsed_translations, parse_error = _parse_translation_response(content or "")

    if parse_error:
        return [], parse_error

    valid_translations = _validate_translations_against_source(
        source_items=batch,
        translations=parsed_translations,
        model_name=config.model_name,
    )

    if not valid_translations:
        return [], "La respuesta IA fue válida, pero no produjo traducciones útiles."

    return valid_translations, None


def _translate_batch_with_fallback(
    batch: List[Dict[str, Any]],
    config: HsecscanAiTranslationConfig,
    batch_index: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Traduce un lote con fallback.

    - Primero intenta el lote.
    - Si falla y hay más de un registro, intenta uno por uno.
    """
    batch_meta: Dict[str, Any] = {
        "batch_index": batch_index,
        "items": len(batch),
        "translated_items": 0,
        "error": None,
        "fallback_used": False,
        "fallback_errors": [],
        "recovered_from_batch_error": None,
    }

    translations, error = _translate_batch_once(batch, config)

    if not error:
        batch_meta["translated_items"] = len(translations)
        return translations, batch_meta

    if len(batch) <= 1:
        batch_meta["error"] = error
        return [], batch_meta

    batch_meta["fallback_used"] = True
    batch_meta["recovered_from_batch_error"] = error

    recovered_translations: List[Dict[str, Any]] = []

    for item in batch:
        single_translations, single_error = _translate_batch_once([item], config)

        if single_error:
            batch_meta["fallback_errors"].append(
                {
                    "check_id": item.get("check_id"),
                    "error": single_error,
                }
            )
            continue

        recovered_translations.extend(single_translations)

    batch_meta["translated_items"] = len(recovered_translations)

    if not recovered_translations:
        batch_meta["error"] = (
            "El lote falló y el fallback individual tampoco produjo traducciones."
        )

    return recovered_translations, batch_meta
# ==========================================================
# API PÚBLICA DEL SERVICIO
# ==========================================================

def translate_hsecscan_checks_with_ai(
    checks: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Traduce checks de hsecscan usando IA.

    Parámetros:
    - checks: filas devueltas por db.list_hsecscan_checks_for_translation(...)

    Devuelve:
    - translations: lista lista para db.update_hsecscan_check_translations(...)
    - meta: información útil para run_meta.json o logs

    Este método nunca debe romper el escaneo.
    Si algo falla, devuelve lista vacía y registra el error en meta.
    """
    config = _read_config()

    meta: Dict[str, Any] = {
        "enabled": config.enabled,
        "model_name": config.model_name,
        "base_url": config.base_url,
        "requested_checks": len(checks or []),
        "candidate_checks": 0,
        "translated_checks": 0,
        "batches_count": 0,
        "batch_size_effective": config.batch_size,
        "fallback_batches": 0,
        "errors": [],
        "recovered_errors": [],
        "started_at_epoch": time.time(),
        "finished_at_epoch": None,
    }

    if not config.enabled:
        meta["finished_at_epoch"] = time.time()
        meta["skipped_reason"] = "hsecscan_ai_translation_disabled"
        return [], meta

    if not checks:
        meta["finished_at_epoch"] = time.time()
        meta["skipped_reason"] = "no_hsecscan_checks"
        return [], meta

    prepared_items = _build_translation_items(checks, config)
    meta["candidate_checks"] = len(prepared_items)

    if not prepared_items:
        meta["finished_at_epoch"] = time.time()
        meta["skipped_reason"] = "no_translatable_hsecscan_checks"
        return [], meta

    batches = _chunk_items(prepared_items, config.batch_size)
    meta["batches_count"] = len(batches)

    all_translations: List[Dict[str, Any]] = []

    for batch_index, batch in enumerate(batches, start=1):
        batch_translations, batch_meta = _translate_batch_with_fallback(
            batch=batch,
            config=config,
            batch_index=batch_index,
        )

        if batch_meta.get("fallback_used"):
            meta["fallback_batches"] += 1

        if batch_meta.get("recovered_from_batch_error"):
            meta["recovered_errors"].append(
                {
                    "batch_index": batch_index,
                    "items": len(batch),
                    "error": batch_meta.get("recovered_from_batch_error"),
                    "translated_items_after_fallback": batch_meta.get("translated_items", 0),
                }
            )

        if batch_meta.get("fallback_errors"):
            for fallback_error in batch_meta.get("fallback_errors", []):
                meta["errors"].append(
                    {
                        "batch_index": batch_index,
                        "items": 1,
                        "translated_items": 0,
                        "check_id": fallback_error.get("check_id"),
                        "error": fallback_error.get("error"),
                    }
                )

        if batch_meta.get("error"):
            meta["errors"].append(
                {
                    "batch_index": batch_index,
                    "items": len(batch),
                    "translated_items": batch_meta.get("translated_items", 0),
                    "error": batch_meta.get("error"),
                }
            )

        all_translations.extend(batch_translations)

    # Evitar duplicados por seguridad.
    translations_by_id: Dict[int, Dict[str, Any]] = {}

    for item in all_translations:
        try:
            check_id = int(item.get("check_id"))
        except Exception:
            continue

        translations_by_id[check_id] = item

    final_translations = list(translations_by_id.values())

    meta["translated_checks"] = len(final_translations)
    meta["finished_at_epoch"] = time.time()

    if final_translations and not meta["errors"]:
        meta["ok"] = True
    elif final_translations and meta["errors"]:
        meta["ok"] = False
        meta["partial_success"] = True
    else:
        meta["ok"] = False

    return final_translations, meta


def is_hsecscan_ai_translation_enabled() -> bool:
    """
    Permite consultar si la traducción IA está activa.
    """
    return _read_config().enabled