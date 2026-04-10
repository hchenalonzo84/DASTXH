"""
app.py
- Laboratorio XSS mínimo y controlado para pruebas con DASTXH.
- Este laboratorio NO debe exponerse públicamente.
- Está pensado solo para entorno local, aislado y autorizado.

Objetivo:
- ofrecer endpoints simples y parametrizados
- facilitar pruebas con Dalfox
- permitir evidencia clara de reflexión insegura

Rutas:
- /                -> página principal con formularios
- /reflect?q=...   -> refleja el parámetro q sin sanitizar
- /search?q=...    -> variante semántica de búsqueda vulnerable
"""

from __future__ import annotations

from flask import Flask, render_template, request

# ----------------------------------------------------------
# Crear la aplicación Flask
# ----------------------------------------------------------
app = Flask(__name__)


@app.route("/")
def index():
    """
    Página principal del laboratorio.

    Muestra:
    - explicación breve
    - formulario hacia /reflect
    - formulario hacia /search
    """
    return render_template("index.html")


@app.route("/reflect")
def reflect():
    """
    Endpoint deliberadamente inseguro.

    Toma el parámetro q desde la URL y lo envía a la plantilla
    para que se renderice como HTML sin escape.

    Ejemplo:
    /reflect?q=<script>alert(1)</script>

    Esto existe únicamente para pruebas locales controladas.
    """
    q = request.args.get("q", "")
    return render_template("reflect.html", q=q, mode="reflect")


@app.route("/search")
def search():
    """
    Endpoint adicional de búsqueda vulnerable.

    Funciona parecido a /reflect, pero su semántica de búsqueda
    es útil para pruebas DAST más naturales.
    """
    q = request.args.get("q", "")
    return render_template("reflect.html", q=q, mode="search")


if __name__ == "__main__":
    # ------------------------------------------------------
    # Se expone en 0.0.0.0 para que otros contenedores de la
    # misma red Docker puedan alcanzarlo por nombre de servicio.
    # ------------------------------------------------------
    app.run(host="0.0.0.0", port=5000, debug=False)