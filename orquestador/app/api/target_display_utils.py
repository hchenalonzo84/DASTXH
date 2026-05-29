"""
target_display_utils.py
- Utilidades visuales para mostrar URLs objetivo en la GUI de DASTXH.

Problema que resuelve:
- DASTXH usa internamente host.docker.internal para alcanzar servicios
  locales del equipo host desde el contenedor orquestador.
- Esa URL técnica puede confundir al usuario, porque no diferencia si el
  objetivo era:
    1) un laboratorio Docker del prototipo,
    2) un sitio local del equipo host,
    3) un sitio externo/autorizado.

Regla:
- No modifica la URL técnica usada por las herramientas.
- No modifica la URL guardada en base de datos.
- Solo agrega campos amigables para mostrar en la interfaz.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlsplit, urlunsplit


# ==========================================================
# CONSTANTES
# ==========================================================

HOST_DOCKER_INTERNAL = "host.docker.internal"

LOCAL_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
}

DOCKER_LAB_HOSTS = {
    "combo-lab",
    "lab-01-secure-baseline",
    "lab-02-missing-headers",
    "lab-03-weak-csp",
    "lab-04-insecure-cookies",
    "lab-05-xss-basic",
    "lab-06-xss-filtered-partial",
    "lab-07-weak-headers-no-xss",
    "lab-08-good-headers-weak-cookies",
    "lab-09-safe-parameters",
    "lab-10-mixed-controlled",
}


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _safe_text(value: Any) -> str:
    """
    Convierte un valor a texto limpio.
    """
    return str(value or "").strip()


def _get_hostname(url: str) -> str:
    """
    Extrae hostname en minúsculas desde una URL.
    """
    try:
        parsed = urlsplit(_safe_text(url))
        return str(parsed.hostname or "").strip().lower()
    except Exception:
        return ""


def _replace_hostname(url: str, new_hostname: str) -> str:
    """
    Reemplaza únicamente el hostname de una URL.

    Conserva:
    - esquema,
    - puerto,
    - path,
    - query,
    - fragment.
    """
    raw_url = _safe_text(url)

    if not raw_url:
        return raw_url

    try:
        parsed = urlsplit(raw_url)

        if not parsed.scheme or not parsed.netloc:
            return raw_url

        netloc = new_hostname

        if parsed.port:
            netloc = f"{new_hostname}:{parsed.port}"

        return urlunsplit(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

    except Exception:
        return raw_url


def _is_docker_lab_hostname(hostname: str) -> bool:
    """
    Determina si un hostname pertenece a laboratorios Docker DASTXH.
    """
    clean_hostname = _safe_text(hostname).lower()

    if clean_hostname in DOCKER_LAB_HOSTS:
        return True

    return clean_hostname.startswith("lab-")


# ==========================================================
# API PÚBLICA
# ==========================================================

def build_target_url_display(target_url: str) -> Dict[str, Any]:
    """
    Construye campos visuales para una URL objetivo.

    Retorna:
    - target_url_internal: URL técnica real usada por DASTXH.
    - target_url_display: URL amigable para GUI.
    - target_url_kind: código interno de tipo.
    - target_url_kind_label: etiqueta visible para usuario.
    - target_url_help: texto aclaratorio.
    - target_url_is_rewritten: indica si se tradujo host.docker.internal a localhost.
    """
    internal_url = _safe_text(target_url)
    hostname = _get_hostname(internal_url)

    if hostname == HOST_DOCKER_INTERNAL:
        return {
            "target_url_internal": internal_url,
            "target_url_display": _replace_hostname(internal_url, "localhost"),
            "target_url_kind": "host_local",
            "target_url_kind_label": "Servicio local del equipo host",
            "target_url_help": (
                "La URL fue evaluada desde el contenedor usando host.docker.internal, "
                "pero representa un servicio local de la PC anfitriona, como XAMPP, "
                "Nginx local o una aplicación en desarrollo."
            ),
            "target_url_is_rewritten": True,
        }

    if _is_docker_lab_hostname(hostname):
        return {
            "target_url_internal": internal_url,
            "target_url_display": internal_url,
            "target_url_kind": "docker_lab",
            "target_url_kind_label": "Laboratorio Docker DASTXH",
            "target_url_help": (
                "El objetivo pertenece a la red interna de laboratorios Docker "
                "del prototipo."
            ),
            "target_url_is_rewritten": False,
        }

    if hostname in LOCAL_HOSTNAMES:
        return {
            "target_url_internal": internal_url,
            "target_url_display": internal_url,
            "target_url_kind": "host_local_input",
            "target_url_kind_label": "Servicio local del equipo host",
            "target_url_help": (
                "El objetivo apunta a un servicio local del equipo anfitrión."
            ),
            "target_url_is_rewritten": False,
        }

    return {
        "target_url_internal": internal_url,
        "target_url_display": internal_url,
        "target_url_kind": "external",
        "target_url_kind_label": "Objetivo externo/autorizado",
        "target_url_help": (
            "El objetivo no pertenece a los laboratorios internos ni al host local. "
            "Debe evaluarse únicamente si se cuenta con autorización."
        ),
        "target_url_is_rewritten": False,
    }


def enrich_detail_with_target_url_display(detail: Dict[str, Any]) -> Dict[str, Any]:
    """
    Agrega campos visuales de URL a un detail de ejecución.

    No modifica la URL técnica guardada. Solo agrega campos derivados.
    """
    current = dict(detail or {})
    target_url = current.get("target_url") or current.get("url") or ""

    current.update(build_target_url_display(str(target_url)))

    return current


def enrich_execution_row_with_target_url_display(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Agrega campos visuales de URL a una fila de historial o inicio.
    """
    current = dict(row or {})
    target_url = current.get("target_url") or current.get("url") or ""

    current.update(build_target_url_display(str(target_url)))

    return current


def enrich_execution_rows_with_target_url_display(
    rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Agrega campos visuales de URL a varias filas.
    """
    return [
        enrich_execution_row_with_target_url_display(row)
        for row in rows or []
    ]