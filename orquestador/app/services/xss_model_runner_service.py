"""
xss_model_runner_service.py
- Servicio para interpretar grupos XSS con un backend compatible con OpenAI.
- Pensado para Docker Model Runner u otro endpoint local configurable.
- Si la IA no está habilitada o falta configuración, el pipeline sigue normal.
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
    """
    value = str(os.getenv(name, str(default))).strip().lower()
    return value in ("1", "true", "yes", "on")


def _build_chat_completions_url(base_url: str) -> str:
    """
    Permite recibir:
    - http://host:12434/v1
    - http://host:12434/v1/chat/completions
    """
    value = (base_url or "").strip().rstrip("/")
    if value.endswith("/chat/completions"):
        return value
    return f"{value}/chat/completions"


def _strip_code_fences(text: str) -> str:
    """
    Quita fences Markdown si el modelo responde con ```json ... ```
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


# ==========================================================
# CONSTRUCCIÓN DEL PROMPT
# ==========================================================

def _build_messages(xss_ai_payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Construye mensajes para el endpoint compatible con OpenAI.
    """
    entries = xss_ai_payload.get("entries", []) or []

    compact_entries = []
    for index, item in enumerate(entries, start=1):
        # IMPORTANTE:
        # Si por alguna razón group_order no viene, se fuerza aquí.
        group_order = int(item.get("group_order", index) or index)

        compact_entries.append(
            {
                "group_order": group_order,
                "entry_type": item.get("entry_type"),
                "parameter_probable": item.get("parameter_probable"),
                "context_probable": item.get("context_probable"),
                "severity_mode": item.get("severity_mode"),
                "payload_signature": item.get("payload_signature"),
                "occurrences": item.get("occurrences"),
                "sample_finding_orders": item.get("sample_finding_orders"),
                "sample_payloads": item.get("sample_payloads"),
                "sample_evidence": item.get("sample_evidence"),
                "target_url": item.get("target_url"),
            }
        )

    system_prompt = """
Eres un analista de seguridad web.
Debes interpretar hallazgos XSS en español claro, técnico y útil.
NO debes responder de forma genérica.

Debes basarte específicamente en:
- parámetro probable
- contexto probable
- payloads de ejemplo
- evidencia de ejemplo
- severidad observada

Tu salida debe ser SOLO JSON válido con este formato:

{
  "groups": [
    {
      "group_order": 1,
      "interpretation_humana": "Explicación específica de 2 a 4 oraciones sobre qué indica la evidencia, cómo se refleja y por qué eso sugiere el patrón observado.",
      "risk_summary": "Resumen breve del riesgo más probable.",
      "likely_root_cause": "Causa técnica más probable, concreta y no genérica.",
      "recommended_review_area": "Qué parte del frontend/backend debería revisarse.",
      "confidence": "baja|media|alta"
    }
  ]
}

Reglas:
- Debes conservar el mismo group_order que recibes.
- Si la evidencia apunta a enlaces HTML, dilo explícitamente.
- Si la evidencia apunta a formularios, filtros, paginación u opciones de listado, dilo explícitamente.
- Si el payload aparece incrustado en atributos o fragmentos concretos, menciónalo.
- No inventes frameworks, librerías ni componentes internos que no aparezcan en la evidencia.
- No uses frases vacías como "posible XSS reflejado" sin explicar el porqué.
- No escribas recomendaciones vagas como "mejorar la seguridad"; debes indicar qué revisar.
""".strip()

    user_prompt = (
        "Interpreta estos grupos XSS preparados por DASTXH.\n"
        "Cada grupo representa uno o varios hallazgos similares consolidados.\n"
        "Debes usar los payloads y evidencias de ejemplo para dar una interpretación específica.\n\n"
        f"Datos:\n{json.dumps(compact_entries, ensure_ascii=False, indent=2)}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


# ==========================================================
# LLAMADA HTTP
# ==========================================================

def _post_chat_completion(
    url: str,
    body: Dict[str, Any],
    timeout_s: int,
    api_key: str,
) -> str:
    """
    Ejecuta la llamada al backend compatible con OpenAI.
    """
    payload_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

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

def _normalize_interpretation_item(item: Dict[str, Any], fallback_group_order: int) -> Dict[str, Any]:
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


# ==========================================================
# API PÚBLICA
# ==========================================================

def interpret_xss_groups_with_ai(xss_ai_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Intenta interpretar grupos XSS con IA.
    Si no está configurado, devuelve skipped=True y no rompe el pipeline.
    """
    enabled = _env_bool("DASTXH_AI_ENABLED", False)
    base_url = str(os.getenv("DASTXH_AI_BASE_URL", "") or "").strip()
    model_name = str(os.getenv("DASTXH_AI_MODEL", "") or "").strip()
    api_key = str(os.getenv("DASTXH_AI_API_KEY", "not-needed") or "not-needed").strip()
    timeout_s = int(str(os.getenv("DASTXH_AI_TIMEOUT_SECONDS", "120")).strip() or "120")

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

    try:
        url = _build_chat_completions_url(base_url)

        body = {
            "model": model_name,
            "temperature": 0.2,
            "messages": _build_messages(xss_ai_payload),
        }

        raw_text = _post_chat_completion(
            url=url,
            body=body,
            timeout_s=timeout_s,
            api_key=api_key,
        )

        parsed = json.loads(_strip_code_fences(raw_text))

        raw_groups = []
        if isinstance(parsed, dict):
            raw_groups = parsed.get("groups", []) or []
        elif isinstance(parsed, list):
            raw_groups = parsed

        normalized_groups: List[Dict[str, Any]] = []
        for index, raw_item in enumerate(raw_groups, start=1):
            if not isinstance(raw_item, dict):
                continue

            item = _normalize_interpretation_item(raw_item, fallback_group_order=index)
            normalized_groups.append(item)

        return {
            "enabled": True,
            "ok": True,
            "skipped": False,
            "model_name": model_name,
            "groups": normalized_groups,
            "error": None,
        }

    except urllib.error.HTTPError as exc:
        return {
            "enabled": True,
            "ok": False,
            "skipped": False,
            "model_name": model_name,
            "groups": [],
            "error": f"HTTPError {exc.code}: {exc.reason}",
        }
    except Exception as exc:
        return {
            "enabled": True,
            "ok": False,
            "skipped": False,
            "model_name": model_name,
            "groups": [],
            "error": str(exc),
        }


def merge_xss_ai_interpretations(
    prepared_entries: List[Dict[str, Any]],
    interpreted_groups: List[Dict[str, Any]],
    model_name: str | None = None,
) -> List[Dict[str, Any]]:
    """
    Une los grupos preparados con la respuesta interpretada por IA.
    """
    by_order: Dict[int, Dict[str, Any]] = {}

    for item in interpreted_groups:
        group_order = int(item.get("group_order", 0) or 0)
        if group_order > 0:
            by_order[group_order] = item

    merged: List[Dict[str, Any]] = []

    for index, entry in enumerate(prepared_entries, start=1):
        current = dict(entry)

        # IMPORTANTE:
        # Si la entrada preparada no trae group_order, lo forzamos aquí.
        group_order = int(current.get("group_order", index) or index)
        current["group_order"] = group_order

        ai_item = by_order.get(group_order, {})

        current["interpretation_humana"] = ai_item.get("interpretation_humana")
        current["risk_summary"] = ai_item.get("risk_summary")
        current["likely_root_cause"] = ai_item.get("likely_root_cause")
        current["recommended_review_area"] = ai_item.get("recommended_review_area")
        current["confidence"] = ai_item.get("confidence")
        current["model_name"] = model_name

        merged.append(current)

    return merged