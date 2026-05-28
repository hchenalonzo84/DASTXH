"""
labs/scenario-labs/app.py
- Aplicación Flask reutilizable para laboratorios controlados de DASTXH.

Objetivo:
- Proveer varios escenarios de prueba sin crear 10 aplicaciones distintas.
- Cada contenedor define su escenario mediante la variable LAB_SCENARIO.

Escenarios soportados:
1. secure_baseline
2. missing_headers
3. weak_csp
4. insecure_cookies
5. xss_basic
6. xss_filtered_partial
7. weak_headers_no_xss
8. good_headers_weak_cookies
9. safe_parameters
10. mixed_controlled

Uso esperado desde Docker Compose:
- LAB_SCENARIO=secure_baseline
- LAB_SCENARIO=missing_headers
- LAB_SCENARIO=xss_basic
- etc.

Importante:
- Estos laboratorios son para uso académico local.
- No deben publicarse en internet.
- Sirven para validar que DASTXH distinga escenarios seguros,
  débiles, mixtos y vulnerables.
"""

from __future__ import annotations

import os
import re
from html import escape
from typing import Dict

from flask import Flask, Response, jsonify, make_response, request


# ==========================================================
# CONFIGURACIÓN GENERAL
# ==========================================================

app = Flask(__name__)

DEFAULT_SCENARIO = "secure_baseline"

SCENARIO_DESCRIPTIONS: Dict[str, str] = {
    "secure_baseline": (
        "Sitio base con cabeceras de seguridad presentes, cookies seguras "
        "y parámetros escapados."
    ),
    "missing_headers": (
        "Sitio sin cabeceras de seguridad principales. No incluye XSS intencional."
    ),
    "weak_csp": (
        "Sitio con Content-Security-Policy presente, pero débil o permisiva."
    ),
    "insecure_cookies": (
        "Sitio enfocado en cookies inseguras: faltan atributos Secure, HttpOnly "
        "o SameSite."
    ),
    "xss_basic": (
        "Sitio con XSS reflejado básico en parámetros controlados."
    ),
    "xss_filtered_partial": (
        "Sitio con filtro parcial insuficiente. Bloquea algunos patrones, "
        "pero deja pasar otros."
    ),
    "weak_headers_no_xss": (
        "Sitio con cabeceras débiles o ausentes, pero sin XSS porque escapa entradas."
    ),
    "good_headers_weak_cookies": (
        "Sitio con cabeceras razonables, pero cookies inseguras."
    ),
    "safe_parameters": (
        "Sitio con parámetros escapados correctamente y sin XSS intencional."
    ),
    "mixed_controlled": (
        "Sitio mixto: algunas cabeceras faltantes, cookies débiles y XSS reflejado."
    ),
}


# ==========================================================
# HELPERS DE ESCENARIO
# ==========================================================

def get_scenario() -> str:
    """
    Obtiene el escenario activo del laboratorio.

    Si la variable LAB_SCENARIO no existe o no es válida,
    se usa secure_baseline como escenario seguro por defecto.
    """
    scenario = os.getenv("LAB_SCENARIO", DEFAULT_SCENARIO).strip().lower()

    if scenario not in SCENARIO_DESCRIPTIONS:
        return DEFAULT_SCENARIO

    return scenario


def get_lab_name() -> str:
    """
    Obtiene el nombre visible del laboratorio.

    Docker Compose puede enviar LAB_NAME para que cada servicio
    tenga un nombre más amigable en la interfaz.
    """
    return os.getenv("LAB_NAME", "DASTXH Scenario Lab").strip() or "DASTXH Scenario Lab"


def is_secure_headers_scenario(scenario: str) -> bool:
    """
    Indica si el escenario debe responder con cabeceras de seguridad fuertes.
    """
    return scenario in {
        "secure_baseline",
        "safe_parameters",
        "good_headers_weak_cookies",
    }


def is_missing_headers_scenario(scenario: str) -> bool:
    """
    Indica si el escenario debe omitir cabeceras de seguridad relevantes.
    """
    return scenario in {
        "missing_headers",
        "weak_headers_no_xss",
        "xss_basic",
        "insecure_cookies",
        "mixed_controlled",
        "xss_filtered_partial",
    }


def should_use_weak_csp(scenario: str) -> bool:
    """
    Indica si el escenario debe usar una CSP débil.
    """
    return scenario == "weak_csp"


def should_set_secure_cookie(scenario: str) -> bool:
    """
    Indica si debe enviarse una cookie con atributos más seguros.
    """
    return scenario in {
        "secure_baseline",
        "safe_parameters",
    }


def should_set_insecure_cookie(scenario: str) -> bool:
    """
    Indica si debe enviarse una cookie débil para evaluación.
    """
    return scenario in {
        "insecure_cookies",
        "good_headers_weak_cookies",
        "mixed_controlled",
    }


def is_raw_reflection_scenario(scenario: str) -> bool:
    """
    Indica si el escenario refleja entradas sin escape.

    Esto crea un escenario vulnerable controlado para pruebas XSS locales.
    """
    return scenario in {
        "xss_basic",
        "mixed_controlled",
    }


def is_partial_filter_scenario(scenario: str) -> bool:
    """
    Indica si el escenario aplica un filtro parcial inseguro.
    """
    return scenario == "xss_filtered_partial"


# ==========================================================
# HELPERS DE SEGURIDAD / REFLEJO
# ==========================================================

def sanitize_with_partial_filter(value: str) -> str:
    """
    Aplica un filtro parcial intencionalmente insuficiente.

    Bloquea algunas apariciones obvias, pero no realiza escape HTML completo.
    Esto permite un escenario educativo donde ciertos valores pueden seguir
    reflejándose de forma riesgosa.
    """
    if not value:
        return ""

    filtered = re.sub(
        r"(?i)<\s*/?\s*script[^>]*>",
        "[script bloqueado]",
        value,
    )

    filtered = re.sub(
        r"(?i)javascript\s*:",
        "javascript-bloqueado:",
        filtered,
    )

    return filtered


def render_user_value(value: str, scenario: str) -> str:
    """
    Renderiza un valor recibido por parámetro según el escenario activo.

    Escenarios seguros:
    - Escapan HTML.

    Escenarios vulnerables:
    - Reflejan contenido sin escape.

    Escenario de filtro parcial:
    - Aplica filtro insuficiente.
    """
    raw_value = value or ""

    if is_raw_reflection_scenario(scenario):
        return raw_value

    if is_partial_filter_scenario(scenario):
        return sanitize_with_partial_filter(raw_value)

    return escape(raw_value)


def build_nav_links() -> str:
    """
    Construye enlaces de prueba internos para facilitar revisión manual.
    """
    links = [
        ("/", "Inicio"),
        ("/search?q=phone", "Búsqueda"),
        ("/checkout?coupon=SALE10", "Checkout"),
        ("/profile?name=Ana", "Perfil"),
        ("/comments?message=Hola", "Comentarios"),
        ("/login?username=demo", "Login"),
        ("/headers", "Headers"),
        ("/health", "Health"),
    ]

    items = "\n".join(
        f'<a class="nav-link" href="{href}">{label}</a>'
        for href, label in links
    )

    return f'<nav class="nav">{items}</nav>'


def page_layout(title: str, body: str, scenario: str) -> str:
    """
    Construye una página HTML simple y consistente para todos los escenarios.
    """
    lab_name = escape(get_lab_name())
    scenario_text = escape(scenario)
    description = escape(SCENARIO_DESCRIPTIONS.get(scenario, ""))

    return f"""
<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>{escape(title)} - {lab_name}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {{
            --bg: #0f172a;
            --panel: #111827;
            --panel-soft: #172033;
            --border: #334155;
            --text: #e5e7eb;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #f87171;
            --success: #86efac;
            --warning: #fbbf24;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
        }}

        .container {{
            max-width: 1050px;
            margin: 0 auto;
            padding: 32px 20px;
        }}

        .card {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px;
            margin-bottom: 18px;
        }}

        .title {{
            margin-top: 0;
            margin-bottom: 8px;
        }}

        .muted {{
            color: var(--muted);
        }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            background: var(--panel-soft);
            border: 1px solid var(--border);
            font-size: 13px;
            font-weight: bold;
        }}

        .nav {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 16px;
        }}

        .nav-link {{
            color: var(--accent);
            text-decoration: none;
            padding: 8px 10px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: #0b1220;
        }}

        .nav-link:hover {{
            text-decoration: underline;
        }}

        .result {{
            background: #0b1220;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            margin-top: 12px;
            overflow-wrap: anywhere;
        }}

        code {{
            background: #0b1220;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 2px 6px;
        }}

        label {{
            display: block;
            margin-top: 12px;
            margin-bottom: 6px;
            font-weight: bold;
        }}

        input {{
            width: 100%;
            padding: 10px;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: #0b1220;
            color: var(--text);
        }}

        button {{
            margin-top: 10px;
            padding: 10px 14px;
            border: 0;
            border-radius: 10px;
            background: var(--accent);
            color: #00111f;
            font-weight: bold;
            cursor: pointer;
        }}

        .warning {{
            border-left: 4px solid var(--warning);
        }}

        .success {{
            border-left: 4px solid var(--success);
        }}

        .danger {{
            border-left: 4px solid var(--danger);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1 class="title">{lab_name}</h1>
            <span class="badge">Escenario: {scenario_text}</span>
            <p class="muted">{description}</p>
            {build_nav_links()}
        </div>

        {body}
    </div>
</body>
</html>
"""
# ==========================================================
# RESPUESTAS, CABECERAS Y COOKIES POR ESCENARIO
# ==========================================================

def make_lab_response(html: str, scenario: str) -> Response:
    """
    Construye la respuesta HTTP y agrega cabeceras/cookies
    según el escenario activo.
    """
    response = make_response(html)

    apply_scenario_headers(response=response, scenario=scenario)
    apply_scenario_cookies(response=response, scenario=scenario)

    return response


def apply_scenario_headers(response: Response, scenario: str) -> None:
    """
    Aplica cabeceras de seguridad según el escenario.

    DASTXH debe poder observar diferencias entre:
    - sitios con cabeceras presentes;
    - sitios con cabeceras ausentes;
    - sitios con CSP débil.
    """
    if is_secure_headers_scenario(scenario):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # HSTS se coloca para que DASTXH pueda detectarla como presente.
        # En HTTP local no tiene efecto real de navegador, pero sirve como
        # evidencia controlada para la capa de cabeceras.
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return

    if should_use_weak_csp(scenario):
        response.headers["Content-Security-Policy"] = (
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
            "script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; "
            "style-src * 'unsafe-inline' data: blob:;"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Intencionalmente se omiten otras cabeceras fuertes.
        return

    if is_missing_headers_scenario(scenario):
        # Escenarios débiles:
        # Se omiten cabeceras principales para que DASTXH registre faltantes.
        return


def apply_scenario_cookies(response: Response, scenario: str) -> None:
    """
    Agrega cookies según el escenario.

    Esto permite que DASTXH observe cookies seguras o débiles
    sin depender de sitios externos.
    """
    if should_set_secure_cookie(scenario):
        response.set_cookie(
            key="lab_secure_session",
            value="secure-demo-session",
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=1800,
        )

    if should_set_insecure_cookie(scenario):
        # Cookie débil intencional:
        # - sin Secure;
        # - sin HttpOnly;
        # - sin SameSite explícito.
        response.headers.add(
            "Set-Cookie",
            "lab_insecure_session=insecure-demo-session; Path=/",
        )

        # Segunda cookie con SameSite=None, pero sin Secure.
        response.headers.add(
            "Set-Cookie",
            "lab_tracking_id=tracking-demo; Path=/; SameSite=None",
        )


# ==========================================================
# RUTAS PRINCIPALES
# ==========================================================

@app.get("/")
def home() -> Response:
    """
    Página inicial del laboratorio activo.
    """
    scenario = get_scenario()

    body = f"""
    <div class="card">
        <h2>Laboratorio activo</h2>
        <p>
            Este contenedor ejecuta un escenario controlado para pruebas
            educativas de DASTXH.
        </p>

        <div class="result">
            <strong>Escenario:</strong> <code>{escape(scenario)}</code><br>
            <strong>Nombre:</strong> <code>{escape(get_lab_name())}</code>
        </div>

        <p class="muted">
            Usa las rutas de navegación para generar tráfico de prueba.
            DASTXH puede evaluar este laboratorio por nombre interno Docker
            o por puerto local si el servicio está expuesto.
        </p>
    </div>
    """

    html = page_layout(
        title="Inicio",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/search")
def search() -> Response:
    """
    Ruta de búsqueda.

    Parámetro:
    - q

    En escenarios vulnerables, q puede reflejarse sin escape.
    En escenarios seguros, q se escapa correctamente.
    """
    scenario = get_scenario()
    q = request.args.get("q", "")
    rendered_q = render_user_value(q, scenario)

    body = f"""
    <div class="card">
        <h2>Búsqueda de productos</h2>
        <form method="get" action="/search">
            <label for="q">Buscar</label>
            <input id="q" name="q" value="{escape(q)}" placeholder="Ejemplo: phone">
            <button type="submit">Buscar</button>
        </form>

        <div class="result">
            <strong>Resultado para:</strong> {rendered_q}
        </div>

        <p class="muted">
            Esta ruta permite observar cómo el escenario maneja parámetros
            reflejados en la respuesta HTML.
        </p>
    </div>
    """

    html = page_layout(
        title="Búsqueda",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/checkout")
def checkout() -> Response:
    """
    Ruta de checkout.

    Parámetro:
    - coupon

    En escenarios vulnerables, coupon puede reflejarse sin escape.
    """
    scenario = get_scenario()
    coupon = request.args.get("coupon", "")
    rendered_coupon = render_user_value(coupon, scenario)

    body = f"""
    <div class="card">
        <h2>Checkout</h2>
        <form method="get" action="/checkout">
            <label for="coupon">Cupón</label>
            <input id="coupon" name="coupon" value="{escape(coupon)}" placeholder="SALE10">
            <button type="submit">Aplicar cupón</button>
        </form>

        <div class="result">
            <strong>Cupón recibido:</strong> {rendered_coupon}
        </div>

        <p class="muted">
            Esta ruta es útil para comparar hallazgos XSS entre escenarios
            seguros, vulnerables y mixtos.
        </p>
    </div>
    """

    html = page_layout(
        title="Checkout",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/profile")
def profile() -> Response:
    """
    Ruta de perfil.

    Parámetro:
    - name
    """
    scenario = get_scenario()
    name = request.args.get("name", "")
    rendered_name = render_user_value(name, scenario)

    body = f"""
    <div class="card">
        <h2>Perfil de usuario</h2>
        <form method="get" action="/profile">
            <label for="name">Nombre</label>
            <input id="name" name="name" value="{escape(name)}" placeholder="Ana">
            <button type="submit">Actualizar vista</button>
        </form>

        <div class="result">
            <strong>Nombre mostrado:</strong> {rendered_name}
        </div>
    </div>
    """

    html = page_layout(
        title="Perfil",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/comments")
def comments() -> Response:
    """
    Ruta de comentarios.

    Parámetro:
    - message
    """
    scenario = get_scenario()
    message = request.args.get("message", "")
    rendered_message = render_user_value(message, scenario)

    body = f"""
    <div class="card">
        <h2>Comentarios</h2>
        <form method="get" action="/comments">
            <label for="message">Mensaje</label>
            <input id="message" name="message" value="{escape(message)}" placeholder="Hola">
            <button type="submit">Publicar</button>
        </form>

        <div class="result">
            <strong>Comentario publicado:</strong> {rendered_message}
        </div>
    </div>
    """

    html = page_layout(
        title="Comentarios",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)
@app.route("/login", methods=["GET", "POST"])
def login() -> Response:
    """
    Ruta de login simulado.

    Objetivo:
    - Permitir pruebas de reflejo en mensajes de autenticación.
    - El campo username puede reflejarse según el escenario.
    - La contraseña nunca se refleja en la respuesta.

    Parámetros:
    - username
    - password

    Nota:
    - No autentica usuarios reales.
    - Es únicamente un formulario educativo para pruebas locales.
    """
    scenario = get_scenario()

    if request.method == "POST":
        username = request.form.get("username", "")
    else:
        username = request.args.get("username", "")

    rendered_username = render_user_value(username, scenario)

    body = f"""
    <div class="card">
        <h2>Inicio de sesión</h2>

        <form method="post" action="/login">
            <label for="username">Usuario o correo</label>
            <input
                id="username"
                name="username"
                value="{escape(username)}"
                placeholder="demo"
            >

            <label for="password">Contraseña</label>
            <input
                id="password"
                name="password"
                type="password"
                value=""
                placeholder="No se valida"
            >

            <button type="submit">Ingresar</button>
        </form>

        <div class="result warning">
            <strong>Mensaje del sistema:</strong>
            No se encontró una cuenta asociada a: {rendered_username}
        </div>

        <p class="muted">
            Este formulario permite probar cómo se manejan valores reflejados
            en mensajes de autenticación. La contraseña no se muestra en la respuesta.
        </p>
    </div>
    """

    html = page_layout(
        title="Login",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/headers")
def headers_debug() -> Response:
    """
    Ruta informativa para ver qué escenario está activo.

    Ayuda a revisar el tipo de laboratorio sin depender de herramientas externas.
    """
    scenario = get_scenario()

    body = f"""
    <div class="card">
        <h2>Información del escenario</h2>

        <div class="result">
            <strong>Escenario:</strong> <code>{escape(scenario)}</code><br>
            <strong>Cabeceras fuertes:</strong> <code>{str(is_secure_headers_scenario(scenario))}</code><br>
            <strong>CSP débil:</strong> <code>{str(should_use_weak_csp(scenario))}</code><br>
            <strong>Cookies seguras:</strong> <code>{str(should_set_secure_cookie(scenario))}</code><br>
            <strong>Cookies inseguras:</strong> <code>{str(should_set_insecure_cookie(scenario))}</code><br>
            <strong>Reflejo vulnerable:</strong> <code>{str(is_raw_reflection_scenario(scenario))}</code><br>
            <strong>Filtro parcial:</strong> <code>{str(is_partial_filter_scenario(scenario))}</code>
        </div>

        <p class="muted">
            Esta ruta es solo informativa. Las cabeceras reales se observan
            desde las herramientas de DASTXH o desde el inspector del navegador.
        </p>
    </div>
    """

    html = page_layout(
        title="Headers",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario)


@app.get("/health")
def health() -> Response:
    """
    Health check simple del laboratorio.

    Devuelve JSON y conserva cabeceras/cookies del escenario para que
    también pueda ser revisado por herramientas HTTP.
    """
    scenario = get_scenario()

    response = make_response(
        jsonify(
            {
                "ok": True,
                "app": "dastxh-scenario-lab",
                "scenario": scenario,
                "lab_name": get_lab_name(),
            }
        )
    )

    apply_scenario_headers(response=response, scenario=scenario)
    apply_scenario_cookies(response=response, scenario=scenario)

    return response


# ==========================================================
# MANEJO DE ERRORES
# ==========================================================

@app.errorhandler(404)
def not_found(_error) -> Response:
    """
    Página 404 simple para rutas no existentes.
    """
    scenario = get_scenario()

    body = """
    <div class="card">
        <h2>Ruta no encontrada</h2>
        <p>
            La ruta solicitada no existe en este laboratorio.
        </p>
    </div>
    """

    html = page_layout(
        title="404",
        body=body,
        scenario=scenario,
    )

    return make_lab_response(html=html, scenario=scenario), 404