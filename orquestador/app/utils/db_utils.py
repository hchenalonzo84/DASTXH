"""
db_utils.py
- Utilidades relacionadas con espera/conectividad de base de datos.

Responsabilidades:
- Esperar a que PostgreSQL esté disponible antes de continuar.
- Evitar que rutas o servicios repitan la misma lógica de reintento.

Este archivo reemplaza la función wait_for_db que antes estaba en utils.py.
"""

from __future__ import annotations

import time
from typing import Callable


def wait_for_db(ping_fn: Callable[[], None], timeout_s: int = 40) -> None:
    """
    Espera a que la base de datos esté disponible hasta un tiempo máximo.

    Parámetros:
    - ping_fn:
        Función que intenta conectarse o hacer ping a PostgreSQL.
        Si la conexión falla, debe lanzar excepción.
    - timeout_s:
        Tiempo máximo de espera en segundos.

    Comportamiento:
    - Intenta ejecutar ping_fn().
    - Si falla, espera 1 segundo y reintenta.
    - Si se supera timeout_s, lanza RuntimeError con la causa original.

    Ejemplo:
        wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=20)
    """
    start = time.time()

    while True:
        try:
            ping_fn()
            return
        except Exception as exc:
            elapsed = time.time() - start

            if elapsed > timeout_s:
                raise RuntimeError(
                    f"DB no disponible tras {timeout_s}s: {exc}"
                ) from exc

            time.sleep(1)