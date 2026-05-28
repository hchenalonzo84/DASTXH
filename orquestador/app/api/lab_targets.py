"""
lab_targets.py
- Catálogo de laboratorios de prueba disponibles en la GUI de DASTXH.

Objetivo:
- Centralizar las URLs internas Docker y las URLs para navegador.
- Evitar confusión entre:
    * URL que DASTXH debe evaluar dentro de Docker.
    * URL que el usuario abre desde su navegador.
"""

from __future__ import annotations

from typing import Dict, List


def get_lab_targets() -> List[Dict[str, str]]:
    """
    Devuelve la lista oficial de objetivos de laboratorio.

    Campos:
    - group: grupo visual del menú.
    - label: texto visible.
    - url: URL interna Docker para que DASTXH pueda evaluar.
    - browser_url: URL local para abrir desde el navegador del usuario.
    - description: descripción corta del escenario.
    """
    return [
        {
            "group": "Laboratorio base",
            "label": "Combo Lab - Base actual",
            "url": "http://combo-lab:5000",
            "browser_url": "http://localhost:5003",
            "description": "Laboratorio base existente para pruebas conocidas de cabeceras, cookies y XSS.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 01 - Secure Baseline",
            "url": "http://lab-01-secure-baseline:5000",
            "browser_url": "http://localhost:5101",
            "description": "Cabeceras presentes, cookies seguras y parámetros escapados.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 02 - Missing Headers",
            "url": "http://lab-02-missing-headers:5000",
            "browser_url": "http://localhost:5102",
            "description": "Cabeceras de seguridad faltantes, sin XSS intencional.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 03 - Weak CSP",
            "url": "http://lab-03-weak-csp:5000",
            "browser_url": "http://localhost:5103",
            "description": "Content-Security-Policy presente, pero débil o permisiva.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 04 - Insecure Cookies",
            "url": "http://lab-04-insecure-cookies:5000",
            "browser_url": "http://localhost:5104",
            "description": "Cookies con atributos de seguridad incompletos.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 05 - XSS Basic",
            "url": "http://lab-05-xss-basic:5000",
            "browser_url": "http://localhost:5105",
            "description": "XSS reflejado básico en parámetros controlados.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 06 - XSS Filtered Partial",
            "url": "http://lab-06-xss-filtered-partial:5000",
            "browser_url": "http://localhost:5106",
            "description": "Filtro parcial insuficiente para validar comportamiento variable.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 07 - Weak Headers No XSS",
            "url": "http://lab-07-weak-headers-no-xss:5000",
            "browser_url": "http://localhost:5107",
            "description": "Cabeceras débiles, pero parámetros escapados correctamente.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 08 - Good Headers Weak Cookies",
            "url": "http://lab-08-good-headers-weak-cookies:5000",
            "browser_url": "http://localhost:5108",
            "description": "Cabeceras razonables, pero cookies inseguras.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 09 - Safe Parameters",
            "url": "http://lab-09-safe-parameters:5000",
            "browser_url": "http://localhost:5109",
            "description": "Parámetros escapados correctamente y sin XSS intencional.",
        },
        {
            "group": "Escenarios controlados",
            "label": "Lab 10 - Mixed Controlled",
            "url": "http://lab-10-mixed-controlled:5000",
            "browser_url": "http://localhost:5110",
            "description": "Escenario mixto con cabeceras débiles, cookies débiles y XSS controlado.",
        },
    ]