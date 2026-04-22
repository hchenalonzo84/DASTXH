"""
app.py
- Laboratorio XSS estilo tienda online para pruebas con DASTXH.
- Está pensado únicamente para uso local, controlado y autorizado.

Objetivo:
- ofrecer una interfaz más realista
- incluir búsqueda por parámetro GET
- incluir detalle de producto
- incluir formulario de reseñas persistentes
- permitir probar XSS reflejado y XSS persistente
"""

from __future__ import annotations

from flask import Flask, abort, redirect, render_template, request, url_for

import db as db_layer

app = Flask(__name__)


def _clean_text(value: str) -> str:
    """
    Limpieza mínima para campos que no deben quedar vacíos o con espacios.
    """
    return (value or "").strip()


@app.route("/")
def index():
    """
    Portada del laboratorio.

    Muestra:
    - catálogo de productos
    - acceso rápido a búsqueda
    """
    products = db_layer.list_products(limit=20)
    return render_template("index.html", products=products, title="XSS Shop Demo")


@app.route("/search")
def search():
    """
    Búsqueda de productos.

    El parámetro q:
    - se usa para filtrar productos
    - se refleja de forma insegura en la vista
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
    Muestra el detalle de un producto y sus reseñas.

    Las reseñas se renderizan de forma insegura en la plantilla
    para simular XSS persistente.
    """
    product = db_layer.get_product_by_slug(slug)
    if not product:
        abort(404)

    reviews = db_layer.list_reviews_for_product(product_id=product["id"], limit=100)

    return render_template(
        "product_detail.html",
        product=product,
        reviews=reviews,
        error_message=None,
        form_author="",
        form_rating="5",
        form_comment="",
        title=product["name"],
    )


@app.post("/products/<slug>/reviews")
def create_review(slug: str):
    """
    Crea una reseña para un producto.

    Esta ruta es importante para stored XSS:
    - el comentario se guarda en la BD del laboratorio
    - luego se mostrará de forma insegura en el detalle
    """
    product = db_layer.get_product_by_slug(slug)
    if not product:
        abort(404)

    author_name = _clean_text(request.form.get("author_name", ""))
    rating_raw = _clean_text(request.form.get("rating", "5"))
    comment_html = request.form.get("comment_html", "")

    error_message = None

    if not author_name:
        error_message = "El nombre del autor es obligatorio."

    try:
        rating = int(rating_raw)
    except Exception:
        rating = 5

    if rating < 1 or rating > 5:
        error_message = "La calificación debe estar entre 1 y 5."

    if not error_message:
        db_layer.add_review(
            product_id=product["id"],
            author_name=author_name,
            rating=rating,
            comment_html=comment_html,
        )
        return redirect(url_for("product_detail", slug=slug))

    reviews = db_layer.list_reviews_for_product(product_id=product["id"], limit=100)

    return render_template(
        "product_detail.html",
        product=product,
        reviews=reviews,
        error_message=error_message,
        form_author=author_name,
        form_rating=str(rating),
        form_comment=comment_html,
        title=product["name"],
    )


@app.route("/health")
def health():
    """
    Endpoint simple de salud del laboratorio.
    """
    try:
        db_layer.ping_db()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "ok": True,
        "lab": "xss-lab",
        "db_ok": db_ok,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)