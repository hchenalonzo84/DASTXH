"""
hsecscan_classification.py
- Clasificación de registros hsecscan para DASTXH.

Responsabilidad:
- Clasificar cabeceras reportadas por hsecscan en:
    * catálogo principal
    * complementarias vigentes
    * históricas/obsoletas
    * otras observaciones

- Enriquecer filas hsecscan con:
    * header_class
    * header_class_label
    * header_class_description

Nota:
- Este archivo no consulta base de datos.
- Este archivo no ejecuta hsecscan.
- Solo clasifica registros ya persistidos.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import config


def normalize_header_key(value: Any) -> str:
    """
    Normaliza nombres de cabeceras para comparación.

    Ejemplo:
    X_Frame_Options -> x-frame-options
    X-Frame-Options -> x-frame-options
    """
    text = str(value or "").strip().lower()
    text = text.replace("_", "-")

    while "--" in text:
        text = text.replace("--", "-")

    return text


def display_header_name(value: Any) -> str:
    """
    Devuelve un nombre amigable para mostrar en GUI.
    """
    text = str(value or "").strip()
    return text if text else "-"


def config_text(name: str, fallback: str) -> str:
    """
    Lee un texto desde config.py con fallback seguro.
    """
    value = getattr(config, name, fallback)
    text = str(value or "").strip()
    return text if text else fallback


def config_dict(name: str) -> Dict[str, str]:
    """
    Lee un diccionario desde config.py.
    """
    value = getattr(config, name, {})

    if isinstance(value, dict):
        return value

    return {}


def config_header_set(name: str, fallback: Optional[List[str]] = None) -> set[str]:
    """
    Lee una lista de cabeceras desde config.py y la normaliza como set.
    """
    raw_values = getattr(config, name, fallback or [])

    if not isinstance(raw_values, list):
        raw_values = fallback or []

    return {
        normalize_header_key(item)
        for item in raw_values
        if normalize_header_key(item)
    }


def get_header_class_label(header_class: str) -> str:
    """
    Devuelve la etiqueta visual de una clase de cabecera hsecscan.
    """
    labels = config_dict("HSECSCAN_HEADER_CLASS_LABELS")

    fallback_labels = {
        "principal": "Catálogo principal DASTXH",
        "complementaria_vigente": "Observación complementaria vigente",
        "historica_obsoleta": "Referencia histórica/obsoleta",
        "otra_observacion": "Otra observación hsecscan",
    }

    return str(labels.get(header_class) or fallback_labels.get(header_class) or header_class)


def get_header_class_description(header_class: str) -> str:
    """
    Devuelve una explicación visual de una clase de cabecera hsecscan.
    """
    descriptions = config_dict("HSECSCAN_HEADER_CLASS_DESCRIPTIONS")

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


def classify_hsecscan_header(header_name: Any, raw_check_json: Any = None) -> Dict[str, str]:
    """
    Clasifica una cabecera reportada por hsecscan.

    Clasificaciones:
    - principal
    - complementaria_vigente
    - historica_obsoleta
    - otra_observacion
    """
    raw_payload = raw_check_json if isinstance(raw_check_json, dict) else {}

    existing_class = str(raw_payload.get("header_class") or "").strip()

    primary_class = config_text("HSECSCAN_HEADER_CLASS_PRIMARY", "principal")
    complementary_class = config_text(
        "HSECSCAN_HEADER_CLASS_COMPLEMENTARY",
        "complementaria_vigente",
    )
    legacy_class = config_text("HSECSCAN_HEADER_CLASS_LEGACY", "historica_obsoleta")
    other_class = config_text("HSECSCAN_HEADER_CLASS_OTHER", "otra_observacion")

    valid_classes = {
        primary_class,
        complementary_class,
        legacy_class,
        other_class,
    }

    if existing_class in valid_classes:
        header_class = existing_class
    else:
        key = normalize_header_key(header_name)

        primary_headers = config_header_set(
            "HSECSCAN_PRIMARY_COMPARABLE_HEADERS",
            getattr(config, "REQUIRED_HEADERS", []),
        )

        complementary_headers = config_header_set(
            "HSECSCAN_COMPLEMENTARY_CURRENT_HEADERS",
            [],
        )

        legacy_headers = config_header_set(
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
        "header_class_label": raw_payload.get("header_class_label") or get_header_class_label(header_class),
        "header_class_description": raw_payload.get("header_class_description") or get_header_class_description(header_class),
    }


def hsecscan_header_class(item: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    Devuelve la clase DASTXH de un registro hsecscan.
    """
    if not item:
        return None

    header_class = item.get("header_class")

    if header_class:
        return str(header_class)

    classification = classify_hsecscan_header(
        header_name=item.get("header_name"),
        raw_check_json=item.get("raw_check_json"),
    )

    return classification.get("header_class")


def is_hsecscan_primary(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan reporta una cabecera del catálogo principal.
    """
    return hsecscan_header_class(item) == config_text(
        "HSECSCAN_HEADER_CLASS_PRIMARY",
        "principal",
    )


def is_hsecscan_complementary(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan reporta una observación complementaria vigente.
    """
    return hsecscan_header_class(item) == config_text(
        "HSECSCAN_HEADER_CLASS_COMPLEMENTARY",
        "complementaria_vigente",
    )


def is_hsecscan_legacy(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan reporta una cabecera histórica u obsoleta.
    """
    return hsecscan_header_class(item) == config_text(
        "HSECSCAN_HEADER_CLASS_LEGACY",
        "historica_obsoleta",
    )


def is_hsecscan_other_observation(item: Optional[Dict[str, Any]]) -> bool:
    """
    Indica si hsecscan reporta otra observación fuera del catálogo principal.
    """
    return hsecscan_header_class(item) == config_text(
        "HSECSCAN_HEADER_CLASS_OTHER",
        "otra_observacion",
    )


def enrich_hsecscan_check_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Agrega clasificación DASTXH a una fila de hsecscan_checks.
    """
    item = dict(row)
    raw_check_json = item.get("raw_check_json")

    classification = classify_hsecscan_header(
        header_name=item.get("header_name"),
        raw_check_json=raw_check_json,
    )

    item["header_class"] = classification.get("header_class")
    item["header_class_label"] = classification.get("header_class_label")
    item["header_class_description"] = classification.get("header_class_description")

    # Las cabeceras históricas/obsoletas no deben penalizar visualmente.
    if is_hsecscan_legacy(item):
        item["risk_level"] = "informativa"

    return item


def enrich_hsecscan_check_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enriquece todas las filas hsecscan para GUI y comparación.
    """
    return [enrich_hsecscan_check_row(row) for row in rows]