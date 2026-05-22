"""
config.py
- Configuración central del prototipo DASTXH.

Aquí se definen:
  * User-Agent del orquestador
  * cabeceras base a evaluar
  * pesos de scoring HTTP
  * nombres estándar de artifacts/reportes
  * configuración estándar de Dalfox
  * clasificación de cabeceras reportadas por hsecscan
  * estructura editable del Reporte General Profesional

Decisión actual:
- DASTXH ya no expone modo superficial/profundo al usuario.
- El prototipo ejecuta un flujo único: evaluación profunda controlada.
- Dalfox usa una configuración única, estable y controlada.
- La minería de Dalfox puede activarse de forma ligera desde .env.
- En el Reporte General, hsecscan ya no se presenta como sección separada:
  queda integrado dentro de "Análisis de cabeceras HTTP y contraste con hsecscan".
"""

# ----------------------------------------------------------
# User-Agent que usarán las herramientas HTTP del proyecto
# ----------------------------------------------------------
UA = "DASTXH/0.3"


# ==========================================================
# GRUPO A: CABECERAS PRINCIPALES
# ==========================================================

GROUP_A_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

GROUP_A_SCORES = {
    "Content-Security-Policy": -25,
    "Strict-Transport-Security": -20,
    "X-Content-Type-Options": -5,
    "X-Frame-Options": -20,
    "Referrer-Policy": -10,
}

GROUP_A_RECOMMENDATIONS = {
    "Content-Security-Policy": "Implementar una política Content-Security-Policy apropiada para el sitio.",
    "Strict-Transport-Security": "Agregar Strict-Transport-Security y considerar un despliegue progresivo.",
    "X-Content-Type-Options": "Definir X-Content-Type-Options con el valor nosniff.",
    "X-Frame-Options": "Implementar protección contra framing no autorizado mediante X-Frame-Options o frame-ancestors en CSP.",
    "Referrer-Policy": "Definir una política Referrer-Policy apropiada, por ejemplo strict-origin-when-cross-origin.",
}


# ==========================================================
# GRUPO B: AISLAMIENTO / CROSS-ORIGIN
# ==========================================================

GROUP_B_HEADERS = [
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

GROUP_B_SCORES = {
    "Permissions-Policy": -5,
    "Cross-Origin-Opener-Policy": -5,
    "Cross-Origin-Resource-Policy": -5,
    "Cross-Origin-Embedder-Policy": -5,
}

GROUP_B_RECOMMENDATIONS = {
    "Permissions-Policy": "Definir Permissions-Policy para limitar capacidades del navegador según el contexto del sitio.",
    "Cross-Origin-Opener-Policy": "Definir Cross-Origin-Opener-Policy para reforzar el aislamiento del contexto de navegación.",
    "Cross-Origin-Resource-Policy": "Definir Cross-Origin-Resource-Policy para restringir la carga cross-origin según corresponda.",
    "Cross-Origin-Embedder-Policy": "Definir Cross-Origin-Embedder-Policy si el sitio requiere un aislamiento más estricto de recursos embebidos.",
}


# ----------------------------------------------------------
# CORS básico
# ----------------------------------------------------------

CORS_TEST_ID = "cors_basic"
CORS_TEST_NAME = "Cross-Origin Resource Sharing (CORS)"
CORS_SCORE_WILDCARD = -5
CORS_SCORE_WILDCARD_WITH_CREDENTIALS = -15


# ==========================================================
# GRUPO C: COOKIES
# ==========================================================

COOKIE_TESTS = {
    "cookie_secure": {
        "name": "Cookies con atributo Secure",
        "score": -5,
        "recommendation": "Marcar las cookies sensibles con el atributo Secure cuando el sitio opere sobre HTTPS.",
    },
    "cookie_httponly": {
        "name": "Cookies con atributo HttpOnly",
        "score": -5,
        "recommendation": "Aplicar HttpOnly a cookies sensibles para reducir el riesgo de acceso desde scripts del navegador.",
    },
    "cookie_samesite": {
        "name": "Cookies con atributo SameSite",
        "score": -5,
        "recommendation": "Definir SameSite en cookies sensibles para reducir exposición ante ciertos escenarios de ataque.",
    },
}


# ==========================================================
# CONFIGURACIÓN ESTÁNDAR DALFOX
# ==========================================================
# DASTXH usa ahora un solo flujo profundo controlado.
#
# Objetivo de estos valores:
# - reducir variabilidad entre ejecuciones;
# - dar más tiempo a Dalfox para completar pruebas;
# - evitar que URLs públicas dejen la ejecución en running;
# - usar concurrencia moderada;
# - permitir una minería ligera controlada, sin convertir el escaneo
#   en una exploración agresiva.
#
# Todos estos valores pueden sobrescribirse desde .env con:
# - DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS
# - DASTXH_DALFOX_HARD_TIMEOUT_SECONDS
# - DASTXH_DALFOX_WORKERS
# - DASTXH_DALFOX_LIGHT_MINING_ENABLED
# - DASTXH_DALFOX_SKIP_MINING_DOM
# - DASTXH_DALFOX_SKIP_MINING_DICT
# ==========================================================

# Timeout por solicitud individual de Dalfox.
# No es el límite global del proceso.
DALFOX_REQUEST_TIMEOUT_SECONDS = 60

# Timeout duro del proceso completo Dalfox.
# Se deja amplio para pruebas de laboratorio/tesis, pero evita
# que una ejecución quede indefinidamente en running.
DALFOX_HARD_TIMEOUT_SECONDS = 900

# Workers de Dalfox.
# Un valor moderado suele ser más repetible que mucha concurrencia.
DALFOX_WORKERS = 8

# Minería ligera.
# True: permite que Dalfox active minería básica, pero se controlan
#       subtipos de minería desde las opciones siguientes.
# False: agrega --skip-mining-all y desactiva minería.
DALFOX_LIGHT_MINING_ENABLED = True

# Control fino de minería.
# Para una minería muy ligera, se dejan desactivadas las partes más costosas.
# El comportamiento final depende de las opciones soportadas por Dalfox.
DALFOX_SKIP_MINING_DOM = True
DALFOX_SKIP_MINING_DICT = True


# ==========================================================
# COMPATIBILIDAD CON EL MODELO ANTERIOR
# ==========================================================
# Se conserva una lista global de cabeceras para no romper
# partes existentes del backend.
# ==========================================================

REQUIRED_HEADERS = GROUP_A_HEADERS + GROUP_B_HEADERS


# ==========================================================
# CLASIFICACIÓN DE CABECERAS HSECSCAN
# ==========================================================
# hsecscan puede reportar cabeceras modernas, complementarias,
# históricas u obsoletas.
#
# Regla metodológica:
# - curl/DASTXH define el cumplimiento principal.
# - hsecscan refuerza, complementa o contrasta.
# - las cabeceras históricas/obsoletas se conservan como referencia,
#   pero no penalizan el porcentaje principal.
# ==========================================================

HSECSCAN_HEADER_CLASS_PRIMARY = "principal"
HSECSCAN_HEADER_CLASS_COMPLEMENTARY = "complementaria_vigente"
HSECSCAN_HEADER_CLASS_LEGACY = "historica_obsoleta"
HSECSCAN_HEADER_CLASS_OTHER = "otra_observacion"

HSECSCAN_HEADER_CLASS_LABELS = {
    HSECSCAN_HEADER_CLASS_PRIMARY: "Catálogo principal DASTXH",
    HSECSCAN_HEADER_CLASS_COMPLEMENTARY: "Observación complementaria vigente",
    HSECSCAN_HEADER_CLASS_LEGACY: "Referencia histórica/obsoleta",
    HSECSCAN_HEADER_CLASS_OTHER: "Otra observación hsecscan",
}

HSECSCAN_HEADER_CLASS_DESCRIPTIONS = {
    HSECSCAN_HEADER_CLASS_PRIMARY: (
        "Cabecera incluida en el catálogo principal de DASTXH. "
        "hsecscan se usa como contraste para confirmar o ampliar la evidencia."
    ),
    HSECSCAN_HEADER_CLASS_COMPLEMENTARY: (
        "Cabecera o elemento útil para contexto técnico, pero no forma parte "
        "del porcentaje principal de cumplimiento."
    ),
    HSECSCAN_HEADER_CLASS_LEGACY: (
        "Cabecera histórica, antigua, reemplazada o no recomendada como requisito principal actual. "
        "Se conserva como referencia, pero no penaliza el cumplimiento principal."
    ),
    HSECSCAN_HEADER_CLASS_OTHER: (
        "Registro reportado por hsecscan fuera del catálogo principal. "
        "Debe interpretarse como información complementaria."
    ),
}

# Cabeceras de hsecscan que sí son comparables con el catálogo principal.
HSECSCAN_PRIMARY_COMPARABLE_HEADERS = REQUIRED_HEADERS

# Observaciones vigentes o útiles que pueden aportar contexto, pero no forman
# parte del porcentaje principal DASTXH.
HSECSCAN_COMPLEMENTARY_CURRENT_HEADERS = [
    "Cross-Origin Resource Sharing (CORS)",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Server",
    "Set-Cookie",
]

# Cabeceras históricas, antiguas u obsoletas. Se muestran como evidencia
# informativa si hsecscan las reporta, pero no se tratan como requisito actual.
HSECSCAN_LEGACY_OR_HISTORICAL_HEADERS = [
    "X-XSS-Protection",
    "Public-Key-Pins",
    "Expect-CT",
]


# ----------------------------------------------------------
# Nombres estándar de artifacts generados por ejecución
# dentro de /work/reports/<run_id>/
# ----------------------------------------------------------

REPORT_MD = "report.md"
REPORT_HTML = "report.html"
REPORT_PDF = "report.pdf"

HEADERS_JSON = "headers.json"
HSECSCAN_TXT = "hsecscan.txt"
HSECSCAN_JSON = "hsecscan.json"
DALFOX_JSON = "dalfox.json"
DALFOX_TXT = "dalfox.txt"
RUN_META_JSON = "run_meta.json"


# ----------------------------------------------------------
# Tipos lógicos de artifact para registrar en la tabla
# artifacts de PostgreSQL
# ----------------------------------------------------------

ARTIFACT_TYPE_REPORT_MD = "report_md"
ARTIFACT_TYPE_REPORT_HTML = "report_html"
ARTIFACT_TYPE_REPORT_PDF = "report_pdf"
ARTIFACT_TYPE_HEADERS_JSON = "headers_json"
ARTIFACT_TYPE_HSECSCAN_TXT = "hsecscan_txt"
ARTIFACT_TYPE_HSECSCAN_JSON = "hsecscan_json"
ARTIFACT_TYPE_DALFOX_JSON = "dalfox_json"
ARTIFACT_TYPE_DALFOX_TXT = "dalfox_txt"
ARTIFACT_TYPE_RUN_META_JSON = "run_meta_json"

# PDF nuevo del Reporte General Profesional.
ARTIFACT_TYPE_PROFESSIONAL_REPORT_PDF = "professional_report_pdf"


# ----------------------------------------------------------
# MIME types útiles para la tabla artifacts
# ----------------------------------------------------------

MIME_TEXT_MARKDOWN = "text/markdown"
MIME_TEXT_HTML = "text/html"
MIME_APPLICATION_PDF = "application/pdf"
MIME_APPLICATION_JSON = "application/json"
MIME_TEXT_PLAIN = "text/plain"


# ==========================================================
# REPORTE GENERAL PROFESIONAL
# ==========================================================
# El reporte general tiene texto editable + evidencia objetiva.
#
# Importante:
# - No se crea una columna nueva para "cabeceras + hsecscan".
# - Se reutiliza headers_analysis como sección combinada.
# - hsecscan_analysis se deja fuera de los campos editables visibles para
#   evitar duplicación, aunque la columna puede seguir existiendo en BD por
#   compatibilidad.
# ==========================================================

PROFESSIONAL_REPORT_DEFAULT_TITLE = "Reporte general DASTXH"

PROFESSIONAL_REPORT_FILE_PREFIX = "reporte_general"

PROFESSIONAL_REPORT_VERSION_LABEL_PREFIX = "Versión"

PROFESSIONAL_REPORT_STATUS_DRAFT = "draft"
PROFESSIONAL_REPORT_STATUS_AI_GENERATED = "ai_generated"
PROFESSIONAL_REPORT_STATUS_EDITED = "edited"
PROFESSIONAL_REPORT_STATUS_PDF_EXPORTED = "pdf_exported"

PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE = "manual_save"
PROFESSIONAL_REPORT_CHANGE_TYPE_AI_GENERATED = "ai_generated"
PROFESSIONAL_REPORT_CHANGE_TYPE_PDF_EXPORT_SNAPSHOT = "pdf_export_snapshot"

# Campos editables visibles en el formulario y en el PDF.
# hsecscan_analysis NO se muestra separado para evitar duplicación.
PROFESSIONAL_REPORT_EDITABLE_FIELDS = [
    "report_title",
    "executive_summary",
    "scope_text",
    "methodology_text",
    "headers_analysis",
    "cookies_analysis",
    "xss_analysis",
    "prioritized_findings",
    "general_recommendations",
    "limitations_text",
    "conclusion_text",
    "analyst_notes",
]

PROFESSIONAL_REPORT_SECTION_LABELS = {
    "report_title": "Título del reporte",
    "executive_summary": "Resumen ejecutivo",
    "scope_text": "Alcance de la evaluación",
    "methodology_text": "Metodología aplicada",
    "headers_analysis": "Análisis de cabeceras HTTP y contraste con hsecscan",
    "cookies_analysis": "Análisis de cookies observadas",
    "xss_analysis": "Análisis XSS",
    "prioritized_findings": "Hallazgos priorizados",
    "general_recommendations": "Recomendaciones generales",
    "limitations_text": "Limitaciones del análisis",
    "conclusion_text": "Conclusión",
    "analyst_notes": "Notas del analista",
}

PROFESSIONAL_REPORT_SECTION_HELP_TEXTS = {
    "report_title": "Nombre formal del reporte generado para esta ejecución.",
    "executive_summary": (
        "Resume de forma clara el resultado general de la evaluación. "
        "No debe inventar hallazgos; debe basarse en los datos observados."
    ),
    "scope_text": (
        "Describe URL evaluada, alcance de caja negra, fecha de ejecución y capas incluidas."
    ),
    "methodology_text": (
        "Explica brevemente el flujo aplicado por DASTXH: curl, cookies, hsecscan, Dalfox e IA asistida."
    ),
    "headers_analysis": (
        "Interpreta el cumplimiento de cabeceras y el contraste con hsecscan. "
        "La evidencia objetiva debe mostrarse debajo mediante la tabla consolidada curl vs hsecscan."
    ),
    "cookies_analysis": (
        "Interpreta las cookies observadas y sus atributos de seguridad. "
        "La evidencia objetiva debe mostrarse debajo mediante la tabla de cookies."
    ),
    "xss_analysis": (
        "Interpreta los hallazgos XSS detectados o indica si no hubo evidencia válida. "
        "La evidencia objetiva debe mostrarse debajo mediante la tabla XSS."
    ),
    "prioritized_findings": (
        "Enumera los puntos más relevantes que deberían atenderse primero."
    ),
    "general_recommendations": (
        "Presenta acciones recomendadas de mejora o corrección."
    ),
    "limitations_text": (
        "Aclara limitaciones del análisis, respuestas variables, bloqueos, alcance y necesidad de validación manual."
    ),
    "conclusion_text": (
        "Cierra el reporte con una conclusión técnica clara y defendible."
    ),
    "analyst_notes": (
        "Espacio opcional para que el analista agregue observaciones propias."
    ),
}


# ==========================================================
# CONFIGURACIÓN DE EVIDENCIA EN REPORTE GENERAL
# ==========================================================
# Estas constantes serán usadas por la vista y el PDF para mostrar
# las tablas de evidencia debajo del texto editable.
# ==========================================================

PROFESSIONAL_REPORT_EVIDENCE_ENABLED = True

PROFESSIONAL_REPORT_HEADERS_EVIDENCE_TITLE = "Evidencia consolidada curl vs hsecscan"

PROFESSIONAL_REPORT_COOKIES_EVIDENCE_TITLE = "Evidencia de cookies observadas"

PROFESSIONAL_REPORT_XSS_EVIDENCE_TITLE = "Evidencia de hallazgos XSS"

# Límite visual inicial para PDF. La GUI puede mostrar más porque tiene scroll/paginación.
PROFESSIONAL_REPORT_PDF_MAX_HEADER_EVIDENCE_ROWS = 20
PROFESSIONAL_REPORT_PDF_MAX_COOKIE_EVIDENCE_ROWS = 20
PROFESSIONAL_REPORT_PDF_MAX_XSS_EVIDENCE_ROWS = 20