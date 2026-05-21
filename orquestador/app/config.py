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
  * nombres y tipos de artifacts para el reporte general profesional

Decisión actual:
- DASTXH ya no expone modo superficial/profundo al usuario.
- El prototipo ejecuta un flujo único: evaluación profunda controlada.
- Dalfox usa una configuración única, estable y controlada.
- La minería de Dalfox puede activarse de forma ligera desde .env.

Decisión sobre "Cumplimiento de cabeceras":
- El indicador mantiene ese nombre en la GUI.
- El porcentaje se calcula usando el catálogo principal de DASTXH evaluado por curl.
- hsecscan funciona como segunda capa de contraste:
  * confirma hallazgos del catálogo principal;
  * aporta observaciones complementarias;
  * conserva cabeceras históricas/obsoletas como referencia técnica;
  * no penaliza el porcentaje principal por cabeceras antiguas o no recomendadas.

Decisión sobre reporte general profesional:
- El reporte general será una pestaña adicional en el detalle de ejecución.
- El contenido actual editable se guardará en professional_reports.
- Cada guardado creará una versión histórica en professional_report_versions.
- Las versiones históricas serán de solo lectura.
- Los PDF generados se guardarán como artifacts dentro de /work/reports/<run_id>/.
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
# CATÁLOGO PRINCIPAL DASTXH PARA CUMPLIMIENTO
# ==========================================================
# Estas son las cabeceras que cuentan para el indicador
# "Cumplimiento de cabeceras".
#
# Importante:
# - curl es la fuente principal para este indicador.
# - hsecscan puede confirmar o complementar, pero no modifica
#   directamente el porcentaje principal.
# ==========================================================

REQUIRED_HEADERS = GROUP_A_HEADERS + GROUP_B_HEADERS


# ==========================================================
# CLASIFICACIÓN DE CABECERAS HSECSCAN
# ==========================================================
# hsecscan puede reportar cabeceras vigentes, complementarias
# o históricas/obsoletas.
#
# Esta clasificación sirve para:
# - mostrar mejor la comparación curl vs hsecscan;
# - evitar que cabeceras antiguas penalicen el cumplimiento principal;
# - explicar en la GUI si un dato de hsecscan confirma, complementa
#   o solo queda como referencia histórica.
# ==========================================================

HSECSCAN_PRIMARY_COMPARABLE_HEADERS = REQUIRED_HEADERS

HSECSCAN_COMPLEMENTARY_CURRENT_HEADERS = [
    "Server",
    "Content-Type",
    "Set-Cookie",
    "Cache-Control",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
]

HSECSCAN_LEGACY_OR_HISTORICAL_HEADERS = [
    "X-XSS-Protection",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Content-Security-Policy-Report-Only",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "Frame-Options",
    "Pragma",
]

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
        "Cabecera histórica, antigua, no recomendada como requisito principal "
        "o reemplazada por mecanismos modernos. Se conserva como referencia, "
        "pero no penaliza el cumplimiento principal."
    ),
    HSECSCAN_HEADER_CLASS_OTHER: (
        "Registro reportado por hsecscan fuera del catálogo principal. "
        "Debe interpretarse como información complementaria."
    ),
}


# ==========================================================
# REPORTE GENERAL PROFESIONAL
# ==========================================================
# Estos nombres y tipos se usarán para la nueva pestaña:
# "Reporte general".
#
# El contenido editable vive en PostgreSQL:
# - professional_reports
#
# El historial vive en:
# - professional_report_versions
#
# Los PDF exportados se guardan físicamente como artifacts en:
# - /work/reports/<run_id>/
#
# Ejemplo:
# - /work/reports/20260520_213452/reporte_general_v3_20260520_221500.pdf
# ==========================================================

PROFESSIONAL_REPORT_DEFAULT_TITLE = "Reporte general DASTXH"

PROFESSIONAL_REPORT_MD = "reporte_general.md"
PROFESSIONAL_REPORT_HTML = "reporte_general.html"
PROFESSIONAL_REPORT_PDF = "reporte_general.pdf"

PROFESSIONAL_REPORT_FILE_PREFIX = "reporte_general"

PROFESSIONAL_REPORT_VERSION_LABEL_PREFIX = "Versión"

PROFESSIONAL_REPORT_CHANGE_TYPE_AI_GENERATED = "ai_generated"
PROFESSIONAL_REPORT_CHANGE_TYPE_MANUAL_SAVE = "manual_save"
PROFESSIONAL_REPORT_CHANGE_TYPE_PDF_EXPORT_SNAPSHOT = "pdf_export_snapshot"

PROFESSIONAL_REPORT_STATUS_DRAFT = "draft"
PROFESSIONAL_REPORT_STATUS_AI_GENERATED = "ai_generated"
PROFESSIONAL_REPORT_STATUS_EDITED = "edited"
PROFESSIONAL_REPORT_STATUS_PDF_EXPORTED = "pdf_exported"
PROFESSIONAL_REPORT_STATUS_ARCHIVED = "archived"

PROFESSIONAL_REPORT_EDITABLE_FIELDS = [
    "report_title",
    "executive_summary",
    "scope_text",
    "methodology_text",
    "headers_analysis",
    "hsecscan_analysis",
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
    "headers_analysis": "Análisis de cabeceras HTTP",
    "hsecscan_analysis": "Contraste complementario hsecscan",
    "cookies_analysis": "Análisis de cookies",
    "xss_analysis": "Análisis XSS",
    "prioritized_findings": "Hallazgos priorizados",
    "general_recommendations": "Recomendaciones generales",
    "limitations_text": "Limitaciones del análisis",
    "conclusion_text": "Conclusión",
    "analyst_notes": "Notas del analista",
}

PROFESSIONAL_REPORT_SECTION_HELP_TEXTS = {
    "report_title": "Nombre descriptivo del reporte general asociado a esta ejecución.",
    "executive_summary": "Síntesis breve del resultado general, orientada a lectura rápida.",
    "scope_text": "Describe qué URL fue evaluada, qué capas se ejecutaron y qué queda fuera del alcance.",
    "methodology_text": "Explica el flujo usado por DASTXH: curl, hsecscan, cookies, Dalfox e IA asistida.",
    "headers_analysis": "Resume el estado de cabeceras principales y el cumplimiento observado.",
    "hsecscan_analysis": "Explica el papel de hsecscan como contraste técnico complementario.",
    "cookies_analysis": "Resume cookies observadas, atributos faltantes, riesgos y recomendaciones.",
    "xss_analysis": "Resume hallazgos XSS detectados o indica si no hubo evidencia válida.",
    "prioritized_findings": "Enumera los puntos más relevantes que deberían atenderse primero.",
    "general_recommendations": "Presenta acciones recomendadas de mejora o corrección.",
    "limitations_text": "Aclara limitaciones del análisis, respuestas variables, bloqueos, alcance y necesidad de validación manual.",
    "conclusion_text": "Cierra el reporte con una valoración general del resultado.",
    "analyst_notes": "Espacio libre para observaciones manuales del usuario o analista.",
}

PROFESSIONAL_REPORT_SNAPSHOT_FIELDS = PROFESSIONAL_REPORT_EDITABLE_FIELDS.copy()


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
# Se deja amplio como valor base de código. En .env puede reducirse
# a 240 para ejecuciones cercanas a 5 minutos.
DALFOX_HARD_TIMEOUT_SECONDS = 900

# Workers de Dalfox.
# Valor base de código. En .env puede sobrescribirse a 10.
DALFOX_WORKERS = 8

# Minería ligera.
# True: permite que Dalfox active minería básica, pero se controlan
#       subtipos de minería desde las opciones siguientes.
# False: agrega --skip-mining-all y desactiva minería.
DALFOX_LIGHT_MINING_ENABLED = True

# Control fino de minería.
# Valores base. En .env pueden cambiarse a false para permitir
# DOM mining y dict/Gf-Patterns.
DALFOX_SKIP_MINING_DOM = True
DALFOX_SKIP_MINING_DICT = True


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

ARTIFACT_TYPE_PROFESSIONAL_REPORT_MD = "professional_report_md"
ARTIFACT_TYPE_PROFESSIONAL_REPORT_HTML = "professional_report_html"
ARTIFACT_TYPE_PROFESSIONAL_REPORT_PDF = "professional_report_pdf"

ARTIFACT_TYPE_OTHER = "other"


# ----------------------------------------------------------
# MIME types útiles para la tabla artifacts
# ----------------------------------------------------------

MIME_TEXT_MARKDOWN = "text/markdown"
MIME_TEXT_HTML = "text/html"
MIME_APPLICATION_PDF = "application/pdf"
MIME_APPLICATION_JSON = "application/json"
MIME_TEXT_PLAIN = "text/plain"