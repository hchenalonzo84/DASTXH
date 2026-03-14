"""
config.py
- Configuración central del prototipo DASTXH.
- Aquí se definen:
  * User-Agent del orquestador
  * Cabeceras HTTP a evaluar en la capa 1
  * Nombres estándar de artifacts/reportes
"""

# ----------------------------------------------------------
# User-Agent que usarán las herramientas HTTP del proyecto
# ----------------------------------------------------------
UA = "DASTXH/0.2"

# ----------------------------------------------------------
# Cabeceras de seguridad a evaluar en la Capa 1 (curl custom)
# ----------------------------------------------------------
REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
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