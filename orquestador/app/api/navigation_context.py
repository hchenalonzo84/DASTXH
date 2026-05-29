"""
navigation_context.py
- Contexto común para navegación superior de DASTXH.

Objetivo:
- Evitar duplicar lógica en las rutas principales.
- Enviar a los templates:
    * catálogo de laboratorios
    * URL visible de Grafana para el navegador del usuario

Uso:
- routes_home.py
- routes_web_history.py
- routes_execution_detail.py
"""

from __future__ import annotations

import os
from typing import Any, Dict
from urllib.parse import urlencode

from fastapi import Request

from api.lab_targets import get_lab_targets


# ==========================================================
# URL DE GRAFANA PARA EL NAVEGADOR
# ==========================================================

def build_grafana_dashboard_url(request: Request) -> str:
    """
    Construye la URL de Grafana para abrir desde el navegador del usuario.

    Importante:
    - No usa la red interna Docker.
    - Usa el hostname visible desde el navegador, normalmente localhost.
    - Usa GRAFANA_PORT si existe; si no, usa 3000.
    """
    scheme = request.url.scheme or "http"
    hostname = request.url.hostname or "localhost"

    grafana_port = os.getenv("GRAFANA_PORT", "3000").strip() or "3000"

    query = urlencode(
        {
            "orgId": "1",
            "from": "now-30d",
            "to": "now",
            "timezone": "browser",
            "refresh": "10s",
        }
    )

    return f"{scheme}://{hostname}:{grafana_port}/?{query}"


# ==========================================================
# CONTEXTO COMÚN DE NAVEGACIÓN
# ==========================================================

def build_navigation_context(request: Request) -> Dict[str, Any]:
    """
    Devuelve variables comunes para el menú superior.
    """
    return {
        "lab_targets": get_lab_targets(),
        "grafana_dashboard_url": build_grafana_dashboard_url(request),
    }