"""
config.py
- Configuración central del prototipo DASTXH.

Aquí se definen:
  * User-Agent del orquestador.
  * zona horaria de visualización del prototipo.
  * etiquetas en español para estados internos.
  * cabeceras base a evaluar.
  * pesos de scoring HTTP.
  * nombres estándar de archivos generados.
  * configuración estándar de Dalfox.
  * clasificación de cabeceras reportadas por hsecscan.
  * mapeo interno CWE para evidencias generadas por DASTXH.
  * estructura editable del Reporte General.

Decisión actual:
- DASTXH ya no expone modo superficial/profundo al usuario.
- El prototipo ejecuta un flujo único: evaluación profunda controlada.
- Dalfox usa una configuración única, estable y controlada.
- La minería de Dalfox puede activarse de forma ligera desde .env.
- En el Reporte General, hsecscan no se presenta como sección separada:
  queda integrado dentro de "Análisis de cabeceras HTTP y contraste con hsecscan".
- Las fechas deben guardarse preferiblemente en UTC y mostrarse en zona local
  America/Guatemala desde la GUI y PDF.
"""

# ----------------------------------------------------------
# User-Agent que usarán las herramientas HTTP del proyecto
# ----------------------------------------------------------
UA = "DASTXH/0.3"


# ==========================================================
# ZONA HORARIA Y FORMATO GLOBAL DE FECHA/HORA
# ==========================================================
# Regla recomendada:
# - PostgreSQL puede conservar fechas en UTC.
# - DASTXH debe mostrar fechas en hora local de Guatemala.
#
# Estos valores se usarán desde:
# - webapp.py como filtro Jinja.
# - templates HTML.
# - servicio PDF.
# ==========================================================

DISPLAY_TIMEZONE = "America/Guatemala"
DISPLAY_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# ==========================================================
# ETIQUETAS EN ESPAÑOL PARA ESTADOS INTERNOS
# ==========================================================

EXECUTION_STATUS_LABELS = {
    "initiated": "Iniciada",
    "running": "En progreso",
    "finished": "Finalizada",
    "failed": "Fallida",
    "cancelled": "Cancelada",
}

PROFESSIONAL_REPORT_STATUS_LABELS = {
    "draft": "Borrador",
    "ai_generated": "Generado con IA",
    "edited": "Editado",
    "pdf_exported": "PDF exportado",
    "not_saved": "No guardado",
}

PROFESSIONAL_REPORT_CHANGE_TYPE_LABELS = {
    "manual_save": "Guardado manual",
    "ai_generated": "Generado con IA",
    "pdf_export_snapshot": "Versión para impresión PDF",
}


# ==========================================================
# TEXTOS VISIBLES REUTILIZABLES
# ==========================================================

TECHNICAL_FILES_LABEL = "Archivos técnicos registrados"


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
# MAPEO INTERNO CWE DE DASTXH
# ==========================================================
# Propósito:
# - hsecscan puede traer CWE en varias observaciones.
# - curl_custom / DASTXH genera hallazgos propios que antes quedaban con "-".
# - Este catálogo permite asociar un CWE razonable cuando la evidencia viene
#   del catálogo interno y hsecscan no trae CWE.
#
# Regla metodológica:
# 1. Si hsecscan trae CWE, se usa ese CWE.
# 2. Si hsecscan no trae CWE, se usa este catálogo interno.
# 3. Si no existe mapeo específico, puede usarse CWE-693 como categoría general
#    de mecanismo de protección ausente o insuficiente.
# ==========================================================

DASTXH_INTERNAL_CWE_MAPPINGS = {
    "Content-Security-Policy": (
        "CWE-693: Falla de mecanismo de protección. "
        "También puede relacionarse con CWE-79 cuando la ausencia de una política adecuada "
        "reduce la mitigación frente a secuencias de comandos entre sitios."
    ),
    "Strict-Transport-Security": (
        "CWE-319: Transmisión de información sensible en texto claro. "
        "También puede relacionarse con CWE-311 por ausencia o debilidad de cifrado en tránsito."
    ),
    "X-Content-Type-Options": (
        "CWE-693: Falla de mecanismo de protección asociado a la validación del tipo de contenido."
    ),
    "X-Frame-Options": (
        "CWE-1021: Restricción inadecuada de interfaces renderizadas dentro de marcos o elementos externos."
    ),
    "Referrer-Policy": (
        "CWE-200: Exposición de información sensible a un actor no autorizado."
    ),
    "Permissions-Policy": (
        "CWE-693: Falla de mecanismo de protección por ausencia de restricciones explícitas "
        "sobre capacidades del navegador."
    ),
    "Cross-Origin-Opener-Policy": (
        "CWE-346: Error de validación de origen. "
        "También puede considerarse CWE-693 por ausencia de mecanismo de aislamiento."
    ),
    "Cross-Origin-Resource-Policy": (
        "CWE-346: Error de validación de origen. "
        "También puede considerarse CWE-693 por ausencia de política de aislamiento de recursos."
    ),
    "Cross-Origin-Embedder-Policy": (
        "CWE-346: Error de validación de origen. "
        "También puede considerarse CWE-693 por ausencia de aislamiento estricto de recursos embebidos."
    ),
    "Cross-Origin Resource Sharing (CORS)": (
        "CWE-942: Permisos excesivamente amplios en política de intercambio de recursos entre orígenes."
    ),
    "Access-Control-Allow-Origin": (
        "CWE-942: Permisos excesivamente amplios en política de intercambio de recursos entre orígenes."
    ),
    "Access-Control-Allow-Credentials": (
        "CWE-942: Permisos excesivamente amplios en política de intercambio de recursos entre orígenes."
    ),
    "Cookies con atributo HttpOnly": (
        "CWE-1004: Cookie sensible sin atributo HttpOnly."
    ),
    "Cookies con atributo Secure": (
        "CWE-614: Cookie sensible en sesión HTTPS sin atributo Secure."
    ),
    "Cookies con atributo SameSite": (
        "CWE-1275: Cookie sensible con atributo SameSite ausente o inadecuado."
    ),
    "cookie_httponly": (
        "CWE-1004: Cookie sensible sin atributo HttpOnly."
    ),
    "cookie_secure": (
        "CWE-614: Cookie sensible en sesión HTTPS sin atributo Secure."
    ),
    "cookie_samesite": (
        "CWE-1275: Cookie sensible con atributo SameSite ausente o inadecuado."
    ),
    "Server": (
        "CWE-200: Exposición de información sensible a un actor no autorizado."
    ),
    "Set-Cookie": (
        "CWE-614/CWE-1004/CWE-1275: Revisar atributos Secure, HttpOnly y SameSite según corresponda."
    ),
}

DASTXH_INTERNAL_CWE_ALIASES = {
    "cookie_secure": "Cookies con atributo Secure",
    "cookie_httponly": "Cookies con atributo HttpOnly",
    "cookie_samesite": "Cookies con atributo SameSite",
    "CORS": "Cross-Origin Resource Sharing (CORS)",
}


# ==========================================================
# CONFIGURACIÓN ESTÁNDAR DALFOX
# ==========================================================
# DASTXH usa ahora un solo flujo profundo controlado.
#
# Objetivo de estos valores:
# - reducir variabilidad entre ejecuciones;
# - permitir evaluación DOM XSS con Dalfox de forma controlada;
# - evitar que Dalfox consuma todo el tiempo global de la ejecución;
# - usar concurrencia moderada porque headless consume más recursos;
# - mantener minería DOM y diccionario activas para mejorar cobertura;
# - habilitar flags:
#       --deep-domxss
#       --force-headless-verification
#
# Todos estos valores pueden sobrescribirse desde .env con:
# - DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS
# - DASTXH_DALFOX_HARD_TIMEOUT_SECONDS
# - DASTXH_DALFOX_WORKERS
# - DASTXH_DALFOX_LIGHT_MINING_ENABLED
# - DASTXH_DALFOX_SKIP_MINING_DOM
# - DASTXH_DALFOX_SKIP_MINING_DICT
# - DASTXH_DALFOX_DEEP_DOMXSS_ENABLED
# - DASTXH_DALFOX_FORCE_HEADLESS_VERIFICATION
#
# Nota metodológica:
# - El timeout duro de Dalfox queda en 420 segundos, es decir 7 minutos.
# - Esto deja margen para curl, hsecscan, cookies, IA, reportes y persistencia.
# ==========================================================

DALFOX_REQUEST_TIMEOUT_SECONDS = 25
DALFOX_HARD_TIMEOUT_SECONDS = 420
DALFOX_WORKERS = 6
DALFOX_LIGHT_MINING_ENABLED = True
DALFOX_SKIP_MINING_DOM = False
DALFOX_SKIP_MINING_DICT = False
DALFOX_DEEP_DOMXSS_ENABLED = True
DALFOX_FORCE_HEADLESS_VERIFICATION = True


# ==========================================================
# COMPATIBILIDAD CON EL MODELO ANTERIOR
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

HSECSCAN_PRIMARY_COMPARABLE_HEADERS = REQUIRED_HEADERS

HSECSCAN_COMPLEMENTARY_CURRENT_HEADERS = [
    "Cross-Origin Resource Sharing (CORS)",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Server",
    "Set-Cookie",
]

HSECSCAN_LEGACY_OR_HISTORICAL_HEADERS = [
    "X-XSS-Protection",
    "Public-Key-Pins",
    "Expect-CT",
]


# ----------------------------------------------------------
# Nombres estándar de archivos generados por ejecución
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
# Tipos lógicos de archivo para registrar en PostgreSQL
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

ARTIFACT_TYPE_PROFESSIONAL_REPORT_PDF = "professional_report_pdf"


# ----------------------------------------------------------
# MIME types útiles para la tabla de archivos técnicos
# ----------------------------------------------------------

MIME_TEXT_MARKDOWN = "text/markdown"
MIME_TEXT_HTML = "text/html"
MIME_APPLICATION_PDF = "application/pdf"
MIME_APPLICATION_JSON = "application/json"
MIME_TEXT_PLAIN = "text/plain"


# ==========================================================
# REPORTE GENERAL
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

PROFESSIONAL_REPORT_EVIDENCE_ENABLED = True

PROFESSIONAL_REPORT_HEADERS_EVIDENCE_TITLE = "Evidencia consolidada curl vs hsecscan"

PROFESSIONAL_REPORT_COOKIES_EVIDENCE_TITLE = "Evidencia de cookies observadas"

PROFESSIONAL_REPORT_XSS_EVIDENCE_TITLE = "Evidencia de hallazgos XSS"

PROFESSIONAL_REPORT_PDF_MAX_HEADER_EVIDENCE_ROWS = 20
PROFESSIONAL_REPORT_PDF_MAX_COOKIE_EVIDENCE_ROWS = 20
PROFESSIONAL_REPORT_PDF_MAX_XSS_EVIDENCE_ROWS = 20