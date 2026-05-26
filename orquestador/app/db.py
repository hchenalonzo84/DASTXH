"""
db.py
- Fachada temporal de persistencia para DASTXH.

Objetivo:
- Mantener compatibilidad con los imports existentes del proyecto:
      import db as db_layer

- Permitir dividir progresivamente el antiguo db.py grande en repositorios
  más pequeños, sin romper de golpe las rutas, servicios o flujos actuales.

Cómo funciona:
1. Primero importa todo desde db_legacy.py.
   Eso mantiene disponibles las funciones que todavía NO se han migrado.

2. Después importa funciones nuevas desde repositories/.
   Estas funciones sobrescriben a las del legacy cuando tienen el mismo nombre.

Importante:
- NO borrar db_legacy.py todavía.
- db_legacy.py sigue siendo respaldo funcional para todo lo que aún no migramos.
- Este archivo debe quedarse pequeño y actuar como capa de compatibilidad.
"""

from __future__ import annotations


# ==========================================================
# COMPATIBILIDAD TEMPORAL CON EL DB ANTERIOR
# ==========================================================
# Importa todas las funciones anteriores para no romper código
# que todavía dependa de funciones no migradas.
#
# Las funciones migradas se importan después para sobrescribir
# las versiones anteriores cuando tengan el mismo nombre.
from db_legacy import *  # noqa: F401,F403


# ==========================================================
# CONEXIÓN A BASE DE DATOS
# ==========================================================
# Funciones base para crear conexión y verificar disponibilidad.
from repositories.db_connection import (  # noqa: F401
    connect,
    ping_db,
)


# ==========================================================
# EJECUCIONES
# ==========================================================
# Funciones para crear ejecuciones, actualizar estados
# y consultar resumen/historial.
from repositories.execution_repository import (  # noqa: F401
    get_execution_summary,
    insert_execution,
    list_execution_summaries,
    update_execution_finished,
    update_execution_running,
    update_execution_status,
)


# ==========================================================
# DETALLE ENRIQUECIDO DE EJECUCIÓN
# ==========================================================
# Esta función arma el ViewModel completo usado por:
#   /executions/{id}
#
# Incluye:
# - cabeceras presentes/faltantes
# - cookies
# - hsecscan clasificado
# - comparación curl vs hsecscan
# - XSS display rows
# - artifacts
# - reporte general
# - versiones y PDFs del reporte general
from repositories.execution_detail_repository import (  # noqa: F401
    get_execution_detail,
)


# ==========================================================
# RESULTADOS HTTP / CABECERAS / COOKIES INICIALES
# ==========================================================
# insert_header_results guarda:
# - header_results
# - header_checks
# - cookie_checks iniciales
# - http_tests
from repositories.header_repository import (  # noqa: F401
    insert_header_results,
)


# ==========================================================
# COOKIES
# ==========================================================
# Funciones para listar cookies pendientes de interpretación
# y actualizar interpretación/riesgo/CWE/recomendación.
from repositories.cookie_repository import (  # noqa: F401
    list_cookie_checks_for_interpretation,
    update_cookie_check_interpretations,
)


# ==========================================================
# HSECSCAN
# ==========================================================
# Funciones para guardar resultados hsecscan, listar checks
# pendientes de traducción y actualizar traducciones IA.
from repositories.hsecscan_repository import (  # noqa: F401
    insert_hsecscan_results,
    list_hsecscan_checks_for_translation,
    update_hsecscan_check_translations,
)


# ==========================================================
# XSS / DALFOX
# ==========================================================
# Funciones para guardar resultados Dalfox, grupos XSS para IA
# y actualizar interpretaciones de grupos XSS.
from repositories.xss_repository import (  # noqa: F401
    insert_xss_ai_groups,
    insert_xss_results,
    update_xss_ai_group_interpretations,
)


# ==========================================================
# ARTIFACTS / ARCHIVOS GENERADOS
# ==========================================================
# Funciones para registrar y listar archivos generados por ejecución.
from repositories.artifact_repository import (  # noqa: F401
    list_artifacts,
    register_artifact,
)