"""
detail_helpers
- Helpers internos para construir el detalle enriquecido de una ejecución DASTXH.

Objetivo:
- Evitar que execution_detail_repository.py concentre demasiadas líneas.
- Separar responsabilidades:
    * texto y listas
    * clasificación hsecscan
    * comparación curl vs hsecscan
    * visualización XSS
    * consultas SQL del detalle

Nota:
- Estos helpers no ejecutan herramientas externas.
- Estos helpers no llaman IA.
- Solo ayudan a consultar y armar datos para la GUI.
"""