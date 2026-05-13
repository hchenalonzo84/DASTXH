"""
xss_model_runner_service.py
- Servicio para interpretar grupos XSS con un backend compatible con OpenAI.
- Pensado para Docker Model Runner u otro endpoint local configurable.
- Si la IA no está habilitada o falta configuración, el pipeline sigue normal.

Cambios importantes:
- Compacta la información enviada al modelo para evitar prompts enormes.
- Recorta evidencia repetitiva antes de llamar a la IA.
- Procesa los grupos por lotes para evitar HTTP 400 por contexto grande.
- Agrega max_tokens configurable.
- Lee el cuerpo de errores HTTP para diagnosticar mejor.
- Filtra entradas vacías/Unknown antes de pedir interpretación a la IA.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List


# ==========================================================
# HELPERS DE CONFIGURACIÓN
# ==========================================================

def _env_bool(name: str, default: bool = False) -> bool:
    """
    Lee un booleano desde variables de entorno.

    Acepta:
    - 1
    - true
    - yes
    - on
    """
    value = str(os.getenv(name, str(default))).strip().lower()
    return value in ("1", "true", "yes", "on")


def _env_int(
    name: str,
    default: int,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    """
    Lee un entero desde variables de entorno con límites opcionales.

    Esto evita que una configuración inválida rompa el pipeline.
    """
    raw_value = str(os.getenv(name, str(default)) or str(default)).strip()

    try:
        value = int(raw_value)
    except Exception:
        value = default

    if min_value is not None:
        value = max(value, min_value)

    if max_value is not None:
        value = min(value, max_value)

    return value


def _env_float(
    name: str,
    default: float,
    min_value: float | None = None,
    max_value: float | None = None,
) -> float:
    """
    Lee un número decimal desde variables de entorno con límites opcionales.
    """
    raw_value = str(os.getenv(name, str(default)) or str(default)).strip()

    try:
        value = float(raw_value)
    except Exception:
        value = default

    if min_value is not None:
        value = max(value, min_value)

    if max_value is not None:
        value = min(value, max_value)

    return value


def _build_chat_completions_url(base_url: str) -> str:
    """
    Construye la URL final del endpoint /chat/completions.

    Permite recibir:
    - http://host:12434/v1
    - http://host:12434/engines/v1
    - http://host:12434/v1/chat/completions
    - http://host:12434/engines/v1/chat/completions
    """
    value = (base_url or "").strip().rstrip("/")

    if value.endswith("/chat/completions"):
        return value

    return f"{value}/chat/completions"


def _strip_code_fences(text: str) -> str:
    """
    Quita fences Markdown si el modelo responde con:

    ```json
    {...}
    ```
    """
    raw = (text or "").strip()

    if raw.startswith("```"):
        lines = raw.splitlines()

        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        return "\n".join(lines).strip()

    return raw


def _clean_text(value: Any) -> str:
    """
    Normaliza texto para reducir ruido antes de enviarlo a la IA.

    - Convierte None a cadena vacía.
    - Elimina saltos de línea repetitivos.
    - Colapsa espacios múltiples.
    """
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return " ".join(text.split())


def _truncate_text(value: Any, max_chars: int) -> str:
    """
    Recorta texto largo conservando una señal clara de truncamiento.
    """
    text = _clean_text(value)

    if max_chars <= 0:
        return text

    if len(text) <= max_chars:
        return text

    return text[:max_chars].rstrip() + "..."


def _compact_string_list(
    values: Any,
    max_items: int,
    max_chars_per_item: int,
) -> List[str]:
    """
    Compacta una lista de textos.

    Se usa para:
    - payloads representativos
    - evidencias representativas

    También elimina valores vacíos y duplicados exactos para reducir tokens.
    """
    if not isinstance(values, list):
        return []

    result: List[str] = []
    seen: set[str] = set()

    for raw_item in values:
        text = _truncate_text(raw_item, max_chars=max_chars_per_item)

        if not text:
            continue

        if text in seen:
            continue

        seen.add(text)
        result.append(text)

        if len(result) >= max_items:
            break

    return result


def _looks_empty_or_unknown_entry(item: Dict[str, Any]) -> bool:
    """
    Detecta grupos/hallazgos que no aportan una evidencia XSS real.

    Caso típico observado:
    - severity_mode = Unknown
    - payload_signature = payload_desconocido
    - sample_payloads vacío
    - sample_evidence vacío

    Estos elementos no deben enviarse a la IA si existen otros hallazgos válidos.
    """
    severity = str(item.get("severity_mode", "") or "").strip().lower()
    signature = str(item.get("payload_signature", "") or "").strip().lower()
    parameter = str(item.get("parameter_probable", "") or "").strip().lower()

    sample_payloads = item.get("sample_payloads") or []
    sample_evidence = item.get("sample_evidence") or []

    has_payloads = isinstance(sample_payloads, list) and any(_clean_text(x) for x in sample_payloads)
    has_evidence = isinstance(sample_evidence, list) and any(_clean_text(x) for x in sample_evidence)

    is_unknown = severity in ("", "unknown", "-", "desconocido")
    is_unknown_signature = signature in ("", "payload_desconocido", "unknown", "-")
    is_unknown_parameter = parameter in ("", "-", "desconocido", "unknown")

    return is_unknown and is_unknown_signature and is_unknown_parameter and not has_payloads and not has_evidence


def _compact_entry_for_model(
    item: Dict[str, Any],
    fallback_group_order: int,
    max_payloads: int,
    max_payload_chars: int,
    max_evidence_items: int,
    max_evidence_chars: int,
) -> Dict[str, Any]:
    """
    Construye una versión ligera de un grupo XSS para enviarlo al modelo.

    IMPORTANTE:
    No se envían campos muy pesados como:
    - finding_orders completos
    - target_url repetida por cada grupo
    - evidencia completa sin recortar

    La IA solo necesita muestras representativas para explicar el patrón.
    """
    raw_group_order = item.get("group_order", fallback_group_order)

    try:
        group_order = int(raw_group_order or fallback_group_order)
    except Exception:
        group_order = fallback_group_order

    return {
        "group_order": group_order,
        "type": item.get("entry_type") or "group",
        "parameter": item.get("parameter_probable") or "-",
        "context": item.get("context_probable") or "-",
        "severity": item.get("severity_mode") or "-",
        "signature": item.get("payload_signature") or "-",
        "occurrences": item.get("occurrences") or 1,
        "payload_examples": _compact_string_list(
            item.get("sample_payloads"),
            max_items=max_payloads,
            max_chars_per_item=max_payload_chars,
        ),
        "evidence_examples": _compact_string_list(
            item.get("sample_evidence"),
            max_items=max_evidence_items,
            max_chars_per_item=max_evidence_chars,
        ),
    }


def _prepare_entries_for_model(
    xss_ai_payload: Dict[str, Any],
    max_groups: int,
    max_payloads: int,
    max_payload_chars: int,
    max_evidence_items: int,
    max_evidence_chars: int,
) -> List[Dict[str, Any]]:
    """
    Prepara los grupos que sí serán enviados a la IA.

    Reglas:
    - Conserva el group_order original para poder actualizar la BD correctamente.
    - Excluye grupos vacíos/Unknown si existen grupos válidos.
    - Aplica límite máximo de grupos para evitar prompts demasiado grandes.
    """
    entries = xss_ai_payload.get("entries", []) or []

    if not isinstance(entries, list):
        return []

    valid_raw_entries: List[Dict[str, Any]] = []

    for raw_item in entries:
        if not isinstance(raw_item, dict):
            continue

        if _looks_empty_or_unknown_entry(raw_item):
            continue

        valid_raw_entries.append(raw_item)

    # Si no hay entradas válidas, no forzamos interpretación artificial.
    if not valid_raw_entries:
        return []

    compact_entries: List[Dict[str, Any]] = []

    for index, item in enumerate(valid_raw_entries, start=1):
        compact_entries.append(
            _compact_entry_for_model(
                item=item,
                fallback_group_order=index,
                max_payloads=max_payloads,
                max_payload_chars=max_payload_chars,
                max_evidence_items=max_evidence_items,
                max_evidence_chars=max_evidence_chars,
            )
        )

        if len(compact_entries) >= max_groups:
            break

    return compact_entries


def _split_batches(entries: List[Dict[str, Any]], batch_size: int) -> List[List[Dict[str, Any]]]:
    """
    Divide los grupos en lotes pequeños.

    Esto evita que Docker Model Runner rechace la solicitud con HTTP 400
    cuando la evidencia de muchos grupos vuelve grande el prompt.
    """
    if batch_size <= 0:
        return [entries]

    return [
        entries[index:index + batch_size]
        for index in range(0, len(entries), batch_size)
    ]


# ==========================================================
# CONSTRUCCIÓN DEL PROMPT
# ==========================================================

def _build_messages(compact_entries: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Construye mensajes compactos para el endpoint compatible con OpenAI.

    Se evita usar indentación en JSON para reducir tokens.
    """
    system_prompt = """
Eres un analista de seguridad web. Interpreta hallazgos XSS reflejado en español claro y técnico.

Responde SOLO JSON válido, sin Markdown, sin texto adicional.

Formato obligatorio:
{
  "groups": [
    {
      "group_order": 1,
      "interpretation_humana": "Máximo 2 oraciones. Explica qué patrón se observa y dónde se refleja.",
      "risk_summary": "Máximo 1 oración.",
      "likely_root_cause": "Máximo 1 oración técnica.",
      "recommended_review_area": "Máximo 1 oración concreta.",
      "confidence": "baja|media|alta"
    }
  ]
}

Reglas:
- Conserva exactamente el group_order recibido.
- No inventes frameworks, tecnologías internas ni archivos que no aparezcan.
- No repitas payloads completos si son largos.
- No digas solo "posible XSS"; explica el patrón observado.
- Si la evidencia apunta a enlaces, filtros, paginación u opciones de listado, menciónalo.
- Si la evidencia no alcanza para alta confianza, usa confidence media o baja.
""".strip()

    data_json = json.dumps(
        compact_entries,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    user_prompt = (
        "Interpreta estos grupos XSS consolidados por DASTXH. "
        "Cada elemento representa varios hallazgos similares o un hallazgo individual. "
        "Usa solo los payload_examples y evidence_examples entregados.\n"
        f"Datos:{data_json}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


# ==========================================================
# LLAMADA HTTP
# ==========================================================

def _format_http_error(exc: urllib.error.HTTPError) -> str:
    """
    Lee el cuerpo del error HTTP para diagnosticar mejor.

    Antes solo se guardaba:
    - HTTPError 400: Bad Request

    Ahora intenta incluir parte del body, que puede decir:
    - context too long
    - invalid request
    - model error
    """
    body = ""

    try:
        body = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        body = ""

    if body:
        body = _truncate_text(body, 1200)
        return f"HTTPError {exc.code}: {exc.reason}. Body: {body}"

    return f"HTTPError {exc.code}: {exc.reason}"


def _post_chat_completion(
    url: str,
    body: Dict[str, Any],
    timeout_s: int,
    api_key: str,
) -> str:
    """
    Ejecuta la llamada al backend compatible con OpenAI.
    """
    payload_bytes = json.dumps(
        body,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=payload_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        raw = response.read().decode("utf-8", errors="replace")

    data = json.loads(raw)
    choices = data.get("choices", []) if isinstance(data, dict) else []

    if not choices:
        raise RuntimeError("La respuesta del modelo no contiene choices.")

    first = choices[0] or {}
    message = first.get("message", {}) if isinstance(first, dict) else {}
    content = message.get("content") if isinstance(message, dict) else None

    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("La respuesta del modelo no contiene contenido textual.")

    return content


# ==========================================================
# NORMALIZACIÓN DE RESPUESTA
# ==========================================================

def _extract_json_from_model_text(text: str) -> Any:
    """
    Intenta extraer JSON aunque el modelo agregue accidentalmente texto extra.

    Orden:
    1. Quitar fences Markdown.
    2. Intentar json.loads directo.
    3. Intentar extraer desde el primer { hasta el último }.
    4. Intentar extraer desde el primer [ hasta el último ].
    """
    raw = _strip_code_fences(text)

    try:
        return json.loads(raw)
    except Exception:
        pass

    first_obj = raw.find("{")
    last_obj = raw.rfind("}")

    if first_obj >= 0 and last_obj > first_obj:
        candidate = raw[first_obj:last_obj + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    first_arr = raw.find("[")
    last_arr = raw.rfind("]")

    if first_arr >= 0 and last_arr > first_arr:
        candidate = raw[first_arr:last_arr + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    snippet = _truncate_text(raw, 700)
    raise RuntimeError(f"La respuesta del modelo no es JSON válido. Respuesta parcial: {snippet}")


def _normalize_interpretation_item(
    item: Dict[str, Any],
    fallback_group_order: int,
) -> Dict[str, Any]:
    """
    Normaliza una interpretación devuelta por el modelo.

    Si el modelo no devuelve group_order correcto, se usa fallback.
    """
    raw_group_order = item.get("group_order", fallback_group_order)

    try:
        group_order = int(raw_group_order or fallback_group_order)
    except Exception:
        group_order = fallback_group_order

    confidence = str(item.get("confidence", "") or "").strip().lower()

    if confidence not in ("baja", "media", "alta"):
        confidence = "media"

    return {
        "group_order": group_order,
        "interpretation_humana": str(item.get("interpretation_humana", "") or "").strip(),
        "risk_summary": str(item.get("risk_summary", "") or "").strip(),
        "likely_root_cause": str(item.get("likely_root_cause", "") or "").strip(),
        "recommended_review_area": str(item.get("recommended_review_area", "") or "").strip(),
        "confidence": confidence,
    }


def _read_groups_from_model_response(
    raw_text: str,
    batch_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Lee y normaliza las interpretaciones devueltas por el modelo para un lote.

    Si el modelo omite group_order en algún item, se usa el group_order del
    grupo correspondiente dentro del lote.
    """
    parsed = _extract_json_from_model_text(raw_text)

    raw_groups: List[Any] = []

    if isinstance(parsed, dict):
        raw_groups = parsed.get("groups", []) or []
    elif isinstance(parsed, list):
        raw_groups = parsed

    if not isinstance(raw_groups, list):
        raise RuntimeError("La respuesta JSON del modelo no contiene una lista 'groups' válida.")

    normalized_groups: List[Dict[str, Any]] = []

    for index, raw_item in enumerate(raw_groups, start=1):
        if not isinstance(raw_item, dict):
            continue

        fallback_group_order = index

        if index <= len(batch_entries):
            fallback_group_order = int(batch_entries[index - 1].get("group_order", index) or index)

        item = _normalize_interpretation_item(
            raw_item,
            fallback_group_order=fallback_group_order,
        )

        # Si el modelo devolvió una interpretación totalmente vacía,
        # no la usamos para evitar actualizar la BD con texto sin valor.
        if not item["interpretation_humana"] and not item["risk_summary"]:
            continue

        normalized_groups.append(item)

    return normalized_groups


# ==========================================================
# API PÚBLICA
# ==========================================================

def interpret_xss_groups_with_ai(xss_ai_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Intenta interpretar grupos XSS con IA.

    Si no está configurado, devuelve skipped=True y no rompe el pipeline.
    Si hay muchos grupos, los interpreta por lotes pequeños.
    """
    enabled = _env_bool("DASTXH_AI_ENABLED", False)
    base_url = str(os.getenv("DASTXH_AI_BASE_URL", "") or "").strip()
    model_name = str(os.getenv("DASTXH_AI_MODEL", "") or "").strip()
    api_key = str(os.getenv("DASTXH_AI_API_KEY", "not-needed") or "not-needed").strip()

    # Timeout por llamada al modelo.
    # Si hay 3 lotes, este timeout aplica a cada lote, no al total.
    timeout_s = _env_int(
        "DASTXH_AI_TIMEOUT_SECONDS",
        default=420,
        min_value=30,
        max_value=1800,
    )

    # Control de salida del modelo.
    # Esto evita respuestas demasiado largas que vuelvan lenta la ejecución.
    max_tokens = _env_int(
        "DASTXH_AI_MAX_TOKENS",
        default=1200,
        min_value=200,
        max_value=4096,
    )

    # Temperatura baja para respuestas más consistentes y JSON más estable.
    temperature = _env_float(
        "DASTXH_AI_TEMPERATURE",
        default=0.1,
        min_value=0.0,
        max_value=1.0,
    )

    # Compactación del prompt.
    max_groups = _env_int(
        "DASTXH_AI_MAX_GROUPS",
        default=20,
        min_value=1,
        max_value=50,
    )

    batch_size = _env_int(
        "DASTXH_AI_BATCH_SIZE",
        default=5,
        min_value=1,
        max_value=20,
    )

    max_payloads = _env_int(
        "DASTXH_AI_MAX_PAYLOADS_PER_GROUP",
        default=2,
        min_value=1,
        max_value=5,
    )

    max_payload_chars = _env_int(
        "DASTXH_AI_MAX_PAYLOAD_CHARS",
        default=180,
        min_value=40,
        max_value=1000,
    )

    max_evidence_items = _env_int(
        "DASTXH_AI_MAX_EVIDENCE_PER_GROUP",
        default=1,
        min_value=1,
        max_value=3,
    )

    max_evidence_chars = _env_int(
        "DASTXH_AI_MAX_EVIDENCE_CHARS",
        default=260,
        min_value=80,
        max_value=1500,
    )

    if not enabled:
        return {
            "enabled": False,
            "ok": False,
            "skipped": True,
            "model_name": None,
            "groups": [],
            "error": None,
        }

    if not base_url or not model_name:
        return {
            "enabled": True,
            "ok": False,
            "skipped": True,
            "model_name": model_name or None,
            "groups": [],
            "error": "Falta configurar DASTXH_AI_BASE_URL o DASTXH_AI_MODEL.",
        }

    compact_entries = _prepare_entries_for_model(
        xss_ai_payload=xss_ai_payload,
        max_groups=max_groups,
        max_payloads=max_payloads,
        max_payload_chars=max_payload_chars,
        max_evidence_items=max_evidence_items,
        max_evidence_chars=max_evidence_chars,
    )

    if not compact_entries:
        return {
            "enabled": True,
            "ok": False,
            "skipped": True,
            "model_name": model_name,
            "groups": [],
            "error": "No hay grupos XSS válidos para interpretar con IA.",
        }

    url = _build_chat_completions_url(base_url)
    batches = _split_batches(compact_entries, batch_size=batch_size)

    all_groups: List[Dict[str, Any]] = []
    batch_errors: List[str] = []

    for batch_index, batch_entries in enumerate(batches, start=1):
        try:
            body = {
                "model": model_name,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False,
                "messages": _build_messages(batch_entries),
            }

            raw_text = _post_chat_completion(
                url=url,
                body=body,
                timeout_s=timeout_s,
                api_key=api_key,
            )

            batch_groups = _read_groups_from_model_response(
                raw_text=raw_text,
                batch_entries=batch_entries,
            )

            all_groups.extend(batch_groups)

        except urllib.error.HTTPError as exc:
            batch_errors.append(f"Lote {batch_index}: {_format_http_error(exc)}")
        except Exception as exc:
            batch_errors.append(f"Lote {batch_index}: {str(exc)}")

    # Elimina duplicados por group_order si el modelo repite algún grupo.
    by_order: Dict[int, Dict[str, Any]] = {}

    for item in all_groups:
        group_order = int(item.get("group_order", 0) or 0)
        if group_order > 0:
            by_order[group_order] = item

    normalized_groups = [
        by_order[group_order]
        for group_order in sorted(by_order.keys())
    ]

    # Si hubo al menos una interpretación, consideramos éxito parcial o total.
    # Esto permite guardar lo que sí se logró interpretar, en vez de perderlo todo.
    if normalized_groups:
        error_text = None

        if batch_errors:
            error_text = "Interpretación parcial. " + " | ".join(batch_errors)

        return {
            "enabled": True,
            "ok": True,
            "skipped": False,
            "model_name": model_name,
            "groups": normalized_groups,
            "error": error_text,
        }

    # Si no se pudo interpretar ningún grupo, se reporta fallo real.
    return {
        "enabled": True,
        "ok": False,
        "skipped": False,
        "model_name": model_name,
        "groups": [],
        "error": " | ".join(batch_errors) if batch_errors else "La IA no devolvió interpretaciones válidas.",
    }


def merge_xss_ai_interpretations(
    prepared_entries: List[Dict[str, Any]],
    interpreted_groups: List[Dict[str, Any]],
    model_name: str | None = None,
) -> List[Dict[str, Any]]:
    """
    Une los grupos preparados con la respuesta interpretada por IA.

    Nota:
    Si algún grupo no fue interpretado por estar vacío, ser Unknown o fallar en
    un lote parcial, sus campos de IA quedan en None. Luego db.py se encargará
    de no renderizar filas vacías cuando existan hallazgos válidos.
    """
    by_order: Dict[int, Dict[str, Any]] = {}

    for item in interpreted_groups:
        try:
            group_order = int(item.get("group_order", 0) or 0)
        except Exception:
            group_order = 0

        if group_order > 0:
            by_order[group_order] = item

    merged: List[Dict[str, Any]] = []

    for index, entry in enumerate(prepared_entries, start=1):
        current = dict(entry)

        # IMPORTANTE:
        # Si la entrada preparada no trae group_order, lo forzamos aquí.
        try:
            group_order = int(current.get("group_order", index) or index)
        except Exception:
            group_order = index

        current["group_order"] = group_order

        ai_item = by_order.get(group_order, {})

        current["interpretation_humana"] = ai_item.get("interpretation_humana")
        current["risk_summary"] = ai_item.get("risk_summary")
        current["likely_root_cause"] = ai_item.get("likely_root_cause")
        current["recommended_review_area"] = ai_item.get("recommended_review_area")
        current["confidence"] = ai_item.get("confidence")
        current["model_name"] = model_name if ai_item else None

        merged.append(current)

    return merged