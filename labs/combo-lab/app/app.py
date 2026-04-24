"""
app.py
- Laboratorio combinado tipo tienda online para pruebas con DASTXH.
- Uso exclusivo en entorno local, controlado y autorizado.

Objetivo:
- simular una app más realista
- ofrecer superficies para XSS reflejado
- exponer cookies inseguras
- dejar ausentes varias cabeceras de seguridad para que
  DASTXH pueda detectarlas en una sola ejecución

Rutas:
- /                    -> catálogo principal
- /search?q=...        -> búsqueda reflejada
- /products/<slug>     -> detalle de producto
- /checkout?coupon=... -> segunda superficie reflejada
- /health              -> salud del laboratorio
"""

from __future__ import annotations

from flask import Flask, abort, render_template, request

import db as db_layer

app = Flask(__name__)


def _clean_text(value: str) -> str:
    """
    Limpieza mínima para texto de entrada.
    """
    return (value or "").strip()


@app.after_request
def apply_intentionally_weak_security_headers(response):
    """
    Ajusta deliberadamente la respuesta para que el laboratorio
    tenga una postura de seguridad débil y detectable por DASTXH.
    """
    response.headers["X-Powered-By"] = "ComboLab Store Demo"

    response.set_cookie(
        key="cart_id",
        value="demo-cart-001",
        max_age=3600,
        path="/",
        secure=False,
        httponly=False,
    )

    response.set_cookie(
        key="prefs_theme",
        value="dark",
        max_age=86400,
        path="/",
        secure=False,
        httponly=False,
    )

    return response


@app.route("/")
def index():
    """
    Portada del laboratorio.
    """
    products = db_layer.list_products(limit=20)

    return render_template(
        "index.html",
        products=products,
        title="Combo Lab Store",
    )


@app.route("/search")
def search():
    """
    Búsqueda de productos.

    El parámetro q:
    - filtra productos desde la BD
    - se mostrará de forma insegura en la plantilla
      para simular XSS reflejado
    """
    q = request.args.get("q", "")
    cleaned_q = _clean_text(q)

    results = []
    if cleaned_q:
        results = db_layer.search_products(cleaned_q, limit=50)

    return render_template(
        "search.html",
        q=q,
        results=results,
        title="Buscar productos",
    )
@app.route("/products/<slug>")
def product_detail(slug: str):
    """
    Muestra un producto individual.
    """
    product = db_layer.get_product_by_slug(slug)
    if not product:
        abort(404)

    return render_template(
        "product_detail.html",
        product=product,
        title=product["name"],
    )


@app.route("/checkout")
def checkout():
    """
    Vista simple para demostrar otra superficie reflejada.

    El parámetro coupon se mostrará de forma insegura
    en la plantilla para simular un caso reflejado.
    """
    coupon = request.args.get("coupon", "")

    return render_template(
        "checkout.html",
        coupon=coupon,
        title="Checkout demo",
    )


@app.route("/health")
def health():
    """
    Endpoint de salud del laboratorio.
    """
    try:
        db_layer.ping_db()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "ok": True,
        "lab": "combo-lab",
        "db_ok": db_ok,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)