"""
main.py
- CLI principal de DASTXH.
- Esta versión ya no contiene toda la lógica del pipeline directamente.
- Ahora delega la ejecución real del escaneo a:
    services.scanner_service.execute_scan

Responsabilidades de este archivo:
  1) Leer argumentos CLI
  2) Validar entorno
  3) Esperar a que PostgreSQL esté disponible
  4) Ejecutar uno o varios escaneos usando el servicio
  5) Mostrar un resumen en consola
  6) Devolver código de salida adecuado

Esto ayuda a:
- evitar duplicación de lógica
- reutilizar el mismo flujo desde CLI, GUI web y API
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any, Dict, List

import db as db_layer
from services.scanner_service import execute_scan
from utils import ensure_dir, load_urls_from_file, wait_for_db


# ==========================================================
# HELPERS DE SALIDA EN CONSOLA
# ==========================================================

def print_scan_summary(result: Dict[str, Any]) -> None:
    """
    Imprime en consola un resumen legible del resultado
    devuelto por execute_scan().
    """
    print("\n=== DASTXH Summary ===")
    print(f"Execution ID: {result.get('execution_id')}")
    print(f"Target:       {result.get('target_url')}")
    print(f"Status:       {result.get('status')}")
    print(f"Source:       {result.get('request_source')}")

    if result.get("ok"):
        print(f"Compliance:   {result.get('compliance_pct')}%")
        print(f"hsecscan rc:  {result.get('hsecscan_rc')}")
        print(f"dalfox rc:    {result.get('dalfox_rc')}")
        print(f"XSS findings: {result.get('findings_count')}")
        print(f"Report dir:   {result.get('report_dir')}")
        print(f"MD report:    {result.get('report_md')}")
        print(f"HTML report:  {result.get('report_html')}")
    else:
        print(f"Error:        {result.get('error')}")
        print(f"Report dir:   {result.get('report_dir')}")


def run_multiple_urls(
    dsn: str,
    workdir: Path,
    urls: List[str],
    timeout_s: int,
) -> int:
    """
    Ejecuta múltiples URLs de forma secuencial usando el servicio
    execute_scan().

    Devuelve:
    - 0 si todas terminan correctamente
    - 1 si al menos una falla
    """
    global_rc = 0

    for url in urls:
        result = execute_scan(
            dsn=dsn,
            workdir=workdir,
            url=url,
            timeout_s=timeout_s,
            request_source="cli",
        )

        print_scan_summary(result)

        if not result.get("ok"):
            global_rc = 1

    return global_rc


# ==========================================================
# ENTRADA PRINCIPAL CLI
# ==========================================================

def main() -> int:
    """
    Punto de entrada principal del modo CLI.

    Soporta:
    - --url       : una sola URL
    - --url-file  : archivo con múltiples URLs
    - --timeout   : timeout en segundos
    """
    parser = argparse.ArgumentParser(description="DASTXH Orquestador (CLI)")
    parser.add_argument("--url", help="URL objetivo (una sola).", default=None)
    parser.add_argument("--url-file", help="Archivo con URLs (opcional).", default=None)
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30")),
        help="Timeout en segundos para herramientas HTTP/DAST.",
    )
    args = parser.parse_args()

    # ------------------------------------------------------
    # Validar cadena de conexión
    # ------------------------------------------------------
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        print("ERROR: DATABASE_URL no está configurada.")
        return 2

    # ------------------------------------------------------
    # Preparar directorio de trabajo
    # ------------------------------------------------------
    workdir = Path(os.getenv("WORKDIR", "/work"))
    ensure_dir(workdir)

    # ------------------------------------------------------
    # Esperar a que la base de datos esté disponible
    # ------------------------------------------------------
    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=40)

    # ------------------------------------------------------
    # Caso 1: una sola URL
    # ------------------------------------------------------
    if args.url:
        result = execute_scan(
            dsn=dsn,
            workdir=workdir,
            url=args.url.strip(),
            timeout_s=args.timeout,
            request_source="cli",
        )

        print_scan_summary(result)
        return 0 if result.get("ok") else 1

    # ------------------------------------------------------
    # Caso 2: archivo con varias URLs
    # ------------------------------------------------------
    if args.url_file:
        urls = load_urls_from_file(Path(args.url_file))
        if not urls:
            print("ERROR: url-file no contiene URLs válidas.")
            return 2

        return run_multiple_urls(
            dsn=dsn,
            workdir=workdir,
            urls=urls,
            timeout_s=args.timeout,
        )

    # ------------------------------------------------------
    # Caso inválido: no se envió ni --url ni --url-file
    # ------------------------------------------------------
    print("ERROR: Debes usar --url o --url-file")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())