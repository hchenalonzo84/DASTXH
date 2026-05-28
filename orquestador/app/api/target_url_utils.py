"""
target_url_utils.py
- Utilidades para normalizar URLs objetivo antes de ejecutar DASTXH.

Objetivo:
- Permitir que DASTXH evalúe:
  1) laboratorios Docker internos,
  2) proyectos locales no contenerizados,
  3) sitios externos autorizados.

Problema resuelto:
- Dentro del contenedor orquestador, "localhost" apunta al propio contenedor,
  no a la PC host.
- Por eso una URL como http://localhost:5105 debe convertirse internamente a:
  http://host.docker.internal:5105

Importante:
- No bloquea sitios externos.
- No modifica URLs internas Docker como http://combo-lab:5000.
- No modifica dominios públicos como https://example.com.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


# ==========================================================
# CONSTANTES
# ==========================================================

LOCAL_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
}

CONTAINER_HOST_GATEWAY = "host.docker.internal"


# ==========================================================
# NORMALIZACIÓN DE URL OBJETIVO
# ==========================================================

def normalize_target_url_for_container(target_url: str) -> str:
    """
    Normaliza una URL para que pueda ser evaluada desde el contenedor orquestador.

    Reglas:
    - http://localhost:PUERTO       -> http://host.docker.internal:PUERTO
    - http://127.0.0.1:PUERTO       -> http://host.docker.internal:PUERTO
    - http://0.0.0.0:PUERTO         -> http://host.docker.internal:PUERTO
    - http://combo-lab:5000         -> se deja igual
    - http://lab-05-xss-basic:5000  -> se deja igual
    - https://sitio-autorizado.com  -> se deja igual

    Retorna:
    - URL efectiva que las herramientas internas deben usar.
    """
    clean_url = (target_url or "").strip()

    if not clean_url:
        return clean_url

    parsed = urlsplit(clean_url)

    # Si la URL no tiene esquema o hostname, se devuelve igual.
    # La validación existente del backend seguirá manejando el error.
    if not parsed.scheme or not parsed.hostname:
        return clean_url

    hostname = parsed.hostname.lower()

    if hostname not in LOCAL_HOSTNAMES:
        return clean_url

    netloc = CONTAINER_HOST_GATEWAY

    if parsed.port:
        netloc = f"{CONTAINER_HOST_GATEWAY}:{parsed.port}"

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )