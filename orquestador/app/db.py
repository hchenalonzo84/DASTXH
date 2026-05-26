"""
db.py
- Fachada limpia de persistencia para DASTXH.

Objetivo:
- Mantener compatibilidad con imports existentes del proyecto:
      import db as db_layer

- Reexportar las funciones públicas desde repositorios especializados.

Estado:
- db_legacy.py ya NO se importa aquí.
- Si todas las pruebas pasan, db_legacy.py puede eliminarse.

Importante:
- Este archivo NO debe volver a concentrar consultas SQL grandes.
- Nueva lógica de base de datos debe ir en repositories/.
"""

from __future__ import annotations


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
# ViewModel completo usado por /executions/{id}.
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


# ==========================================================
# REPORTE GENERAL PROFESIONAL
# ==========================================================
# Funciones para reporte editable, versiones históricas y exportaciones PDF.
from repositories.professional_report_repository import (  # noqa: F401
    create_professional_report_pdf_snapshot_version,
    get_or_create_professional_report,
    get_professional_report,
    get_professional_report_version,
    list_professional_report_pdf_exports,
    list_professional_report_versions,
    register_professional_report_pdf_export,
    save_professional_report,
)