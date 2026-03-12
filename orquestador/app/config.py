"""
config.py
- Configuración central del prototipo DASTXH.
"""

UA = "DASTXH/0.1"

# Cabeceras a evaluar (Capa 1 custom)
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

# Nombres estándar de outputs en /work/reports/<timestamp>/
REPORT_MD = "report.md"
HEADERS_JSON = "headers.json"
HSECSCAN_TXT = "hsecscan.txt"
DALFOX_JSON = "dalfox.json"
DALFOX_TXT = "dalfox.txt"
RUN_META_JSON = "run_meta.json"