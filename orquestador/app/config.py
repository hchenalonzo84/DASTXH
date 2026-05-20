"""
config.py
- Configuración central del prototipo DASTXH.

Aquí se definen:
  * User-Agent del orquestador
  * cabeceras base a evaluar
  * pesos de scoring HTTP
  * nombres estándar de artifacts/reportes
  * configuración estándar de Dalfox

Decisión actual:
- DASTXH ya no expone modo superficial/profundo al usuario.
- El prototipo ejecuta un flujo único: evaluación profunda controlada.
- Dalfox usa una configuración única, estable y controlada.
- La minería de Dalfox puede activarse de forma ligera desde .env.
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


# ----------------------------------------------------------
# MIME types útiles para la tabla artifacts
# ----------------------------------------------------------

MIME_TEXT_MARKDOWN = "text/markdown"
MIME_TEXT_HTML = "text/html"
MIME_APPLICATION_PDF = "application/pdf"
MIME_APPLICATION_JSON = "application/json"
MIME_TEXT_PLAIN = "text/plain"