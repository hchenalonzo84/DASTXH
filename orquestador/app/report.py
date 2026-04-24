"""
report.py
- Construcción de reportes legibles para DASTXH.
- Genera:
  * report.md
  * report.html

Objetivo:
- centralizar la presentación de resultados
- adaptarse a la ejecución real del pipeline
- ocultar hsecscan cuando no aplica
- mostrar score HTTP, grade y pruebas detalladas
- mantener el reporte en español
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _to_list(value: Any) -> List[Any]:
    """
    Normaliza un valor a lista.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _md_bullets(items: List[str], empty_label: str = "- (ninguno)") -> str:
    """
    Convierte una lista de strings en lista Markdown.
    """
    if not items:
        return empty_label
    return "\n".join(f"- {item}" for item in items)


def _html_list(items: List[str], empty_label: str = "(ninguno)") -> str:
    """
    Convierte una lista de strings en una lista HTML.
    """
    if not items:
        return f"<p>{escape(empty_label)}</p>"

    rows = "\n".join(f"<li>{escape(str(item))}</li>" for item in items)
    return f"<ul>\n{rows}\n</ul>"


def _normalize_cookie_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza un registro de cookie para soportar tanto la forma vieja
    como la nueva.
    """
    cookie_raw = item.get("cookie_raw")
    if cookie_raw is None:
        cookie_raw = item.get("cookie", "")

    cookie_name = item.get("cookie_name")
    if cookie_name is not None:
        cookie_name = str(cookie_name).strip() or None

    samesite_present = item.get("samesite_present")
    if samesite_present is None:
        samesite_present = bool(item.get("samesite"))

    samesite_value = item.get("samesite_value")

    return {
        "cookie_name": cookie_name,
        "cookie_raw": str(cookie_raw or ""),
        "secure": bool(item.get("secure")),
        "httponly": bool(item.get("httponly")),
        "samesite_present": bool(samesite_present),
        "samesite_value": samesite_value,
    }


def _cookie_label(cookie_item: Dict[str, Any]) -> str:
    """
    Devuelve una etiqueta legible para identificar una cookie.
    """
    cookie_name = cookie_item.get("cookie_name")
    cookie_raw = cookie_item.get("cookie_raw", "")

    if cookie_name:
        return str(cookie_name)

    if cookie_raw:
        return str(cookie_raw)

    return "(cookie sin identificar)"


def _cookie_flags_md(cookies_flags: List[Dict[str, Any]]) -> str:
    """
    Genera una sección Markdown resumida para las cookies evaluadas.
    """
    if not cookies_flags:
        return "- No se detectaron cookies Set-Cookie en la respuesta final."

    lines: List[str] = []

    for raw_item in cookies_flags:
        item = _normalize_cookie_item(raw_item)

        cookie_label = _cookie_label(item)
        secure = "Sí" if item.get("secure") else "No"
        httponly = "Sí" if item.get("httponly") else "No"
        samesite_present = "Sí" if item.get("samesite_present") else "No"
        samesite_value = item.get("samesite_value") or "-"

        lines.append(f"- Cookie: `{cookie_label}`")
        lines.append(f"  - Secure: **{secure}**")
        lines.append(f"  - HttpOnly: **{httponly}**")
        lines.append(f"  - SameSite presente: **{samesite_present}**")
        lines.append(f"  - Valor SameSite: **{samesite_value}**")

    return "\n".join(lines)


def _cookie_flags_html(cookies_flags: List[Dict[str, Any]]) -> str:
    """
    Genera una sección HTML resumida para las cookies evaluadas.
    """
    if not cookies_flags:
        return "<p>No se detectaron cookies <code>Set-Cookie</code> en la respuesta final.</p>"

    blocks: List[str] = []

    for raw_item in cookies_flags:
        item = _normalize_cookie_item(raw_item)

        cookie_label = escape(_cookie_label(item))
        secure = "Sí" if item.get("secure") else "No"
        httponly = "Sí" if item.get("httponly") else "No"
        samesite_present = "Sí" if item.get("samesite_present") else "No"
        samesite_value = escape(str(item.get("samesite_value") or "-"))

        block = f"""
        <div class="cookie-card">
          <p><strong>Cookie:</strong> <code>{cookie_label}</code></p>
          <ul>
            <li><strong>Secure:</strong> {secure}</li>
            <li><strong>HttpOnly:</strong> {httponly}</li>
            <li><strong>SameSite presente:</strong> {samesite_present}</li>
            <li><strong>Valor SameSite:</strong> {samesite_value}</li>
          </ul>
        </div>
        """
        blocks.append(block.strip())

    return "\n".join(blocks)


def _build_recommendations(hdr_eval: Dict[str, Any]) -> List[str]:
    """
    Construye una lista básica de recomendaciones a partir
    del estado de las cabeceras y cookies.
    """
    recommendations: List[str] = []

    missing = _to_list(hdr_eval.get("missing"))
    cookies_flags = [_normalize_cookie_item(item) for item in _to_list(hdr_eval.get("cookies_flags"))]

    if missing:
        recommendations.append(
            "Agregar o reforzar las cabeceras HTTP de seguridad faltantes según el contexto del sitio."
        )

    if any(not c.get("secure") for c in cookies_flags):
        recommendations.append(
            "Marcar las cookies sensibles con el atributo Secure cuando el sitio opere sobre HTTPS."
        )

    if any(not c.get("httponly") for c in cookies_flags):
        recommendations.append(
            "Aplicar HttpOnly a cookies sensibles para reducir el riesgo de acceso desde scripts del navegador."
        )

    if any(not c.get("samesite_present") for c in cookies_flags):
        recommendations.append(
            "Definir SameSite en cookies sensibles para reducir exposición ante ciertos escenarios de ataque."
        )

    if not recommendations:
        recommendations.append(
            "Mantener las configuraciones actuales y validar periódicamente la exposición de cabeceras y cookies."
        )

    recommendations.append(
        "Si Dalfox reporta hallazgos XSS, validar únicamente en entornos autorizados y corregir sanitización o encoding."
    )

    return recommendations


def _should_include_hsecscan(report_dir: Path, hsecscan_filename: str | None) -> bool:
    """
    Decide si la sección de hsecscan debe mostrarse en el reporte.
    """
    if not hsecscan_filename:
        return False

    try:
        return (report_dir / hsecscan_filename).exists()
    except Exception:
        return False


def _status_label_es(value: str) -> str:
    """
    Traduce estados de pruebas HTTP a español.
    """
    mapping = {
        "passed": "Aprobada",
        "failed": "Falló",
        "warning": "Advertencia",
        "info": "Informativo",
    }
    return mapping.get((value or "").strip().lower(), value or "-")


def _http_tests_md(http_tests: List[Dict[str, Any]]) -> str:
    """
    Construye la sección Markdown de pruebas HTTP.
    """
    if not http_tests:
        return "- No hay pruebas HTTP detalladas registradas."

    lines: List[str] = []
    for item in http_tests:
        lines.append(f"- **{item.get('name', '-') }**")
        lines.append(f"  - Estado: **{_status_label_es(str(item.get('status', '')))}**")
        lines.append(f"  - Puntaje: **{item.get('score_delta', 0)}**")
        lines.append(f"  - Razón: {item.get('reason', '-')}")
        lines.append(f"  - Recomendación: {item.get('recommendation', '-')}")
    return "\n".join(lines)
def _http_tests_html(http_tests: List[Dict[str, Any]]) -> str:
    """
    Construye una tabla HTML de pruebas HTTP.
    """
    if not http_tests:
        return "<p>No hay pruebas HTTP detalladas registradas.</p>"

    rows: List[str] = []
    for item in http_tests:
        rows.append(
            f"""
            <tr>
              <td>{escape(str(item.get("name", "-")))}</td>
              <td>{escape(_status_label_es(str(item.get("status", ""))))}</td>
              <td>{escape(str(item.get("score_delta", 0)))}</td>
              <td>{escape(str(item.get("reason", "-")))}</td>
              <td>{escape(str(item.get("recommendation", "-")))}</td>
            </tr>
            """.strip()
        )

    rows_html = "\n".join(rows)

    return f"""
    <div style="overflow-x:auto;">
      <table style="width:100%; border-collapse:collapse; margin-top:0.75rem;">
        <thead>
          <tr>
            <th style="text-align:left; border-bottom:1px solid #d1d5db; padding:0.6rem;">Prueba</th>
            <th style="text-align:left; border-bottom:1px solid #d1d5db; padding:0.6rem;">Estado</th>
            <th style="text-align:left; border-bottom:1px solid #d1d5db; padding:0.6rem;">Puntaje</th>
            <th style="text-align:left; border-bottom:1px solid #d1d5db; padding:0.6rem;">Razón</th>
            <th style="text-align:left; border-bottom:1px solid #d1d5db; padding:0.6rem;">Recomendación</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
    """


# ==========================================================
# REPORTE MARKDOWN
# ==========================================================

def build_report_md(
    target_url: str,
    report_dir: Path,
    hdr_eval: Dict[str, Any],
    hsecscan_filename: Optional[str],
    dalfox_json_filename: str,
    dalfox_txt_filename: str = "dalfox.txt",
) -> str:
    """
    Construye el contenido del reporte principal en formato Markdown.
    """
    headers_evaluadas = hdr_eval.get("headers_evaluadas", 0)
    headers_presentes = hdr_eval.get("headers_presentes", 0)
    cumplimiento = hdr_eval.get("cumplimiento_pct", 0)
    http_score = hdr_eval.get("http_score", 0)
    http_grade = hdr_eval.get("http_grade", "F")

    present = _to_list(hdr_eval.get("present"))
    missing = _to_list(hdr_eval.get("missing"))
    cookies_flags = _to_list(hdr_eval.get("cookies_flags"))
    http_tests = _to_list(hdr_eval.get("http_tests"))

    present_md = _md_bullets([str(x) for x in present])
    missing_md = _md_bullets([str(x) for x in missing])
    cookies_md = _cookie_flags_md(cookies_flags)
    http_tests_md = _http_tests_md(http_tests)

    recommendations = _build_recommendations(hdr_eval)
    recommendations_md = _md_bullets(recommendations)

    include_hsecscan = _should_include_hsecscan(report_dir, hsecscan_filename)

    hsecscan_md_section = ""
    if include_hsecscan and hsecscan_filename:
        hsecscan_md_section = f"""
## hsecscan

Salida técnica: `{hsecscan_filename}`

> Esta capa complementa la revisión de endurecimiento y exposición visible en cabeceras y cookies.

---
"""

    expected_artifacts = [
        "`report.md`",
        "`report.html`",
        "`headers.json`",
        f"`{dalfox_json_filename}`",
        f"`{dalfox_txt_filename}`",
        "`run_meta.json`",
    ]

    if include_hsecscan and hsecscan_filename:
        expected_artifacts.insert(3, f"`{hsecscan_filename}`")

    expected_artifacts_md = "\n".join(f"- {item}" for item in expected_artifacts)

    return f"""# Reporte DASTXH

**URL objetivo:** {target_url}  
**Carpeta del reporte:** `{report_dir}`

---

## Resumen HTTP

- Cabeceras evaluadas: **{headers_evaluadas}**
- Cabeceras presentes: **{headers_presentes}**
- Cumplimiento: **{cumplimiento}%**
- Puntaje HTTP: **{http_score}/100**
- Nota HTTP: **{http_grade}**

---

## Pruebas HTTP detalladas

{http_tests_md}

---

## Cabeceras presentes
{present_md}

## Cabeceras faltantes
{missing_md}

## Cookies evaluadas
{cookies_md}

> Evidencia principal: `headers.json`

---

{hsecscan_md_section}## Hallazgos XSS (Dalfox)

Salida JSON: `{dalfox_json_filename}`  
Salida técnica: `{dalfox_txt_filename}`

> Revisar la salida estructurada y la evidencia técnica para validar hallazgos en entornos autorizados.

---

## Recomendaciones

{recommendations_md}

---

## Archivos generados esperados

{expected_artifacts_md}
"""


# ==========================================================
# REPORTE HTML
# ==========================================================

def build_report_html(
    target_url: str,
    report_dir: Path,
    hdr_eval: Dict[str, Any],
    hsecscan_filename: Optional[str],
    dalfox_json_filename: str,
    dalfox_txt_filename: str = "dalfox.txt",
) -> str:
    """
    Construye el contenido del reporte en HTML.
    """
    headers_evaluadas = hdr_eval.get("headers_evaluadas", 0)
    headers_presentes = hdr_eval.get("headers_presentes", 0)
    cumplimiento = hdr_eval.get("cumplimiento_pct", 0)
    http_score = hdr_eval.get("http_score", 0)
    http_grade = hdr_eval.get("http_grade", "F")

    present = [str(x) for x in _to_list(hdr_eval.get("present"))]
    missing = [str(x) for x in _to_list(hdr_eval.get("missing"))]
    cookies_flags = _to_list(hdr_eval.get("cookies_flags"))
    http_tests = _to_list(hdr_eval.get("http_tests"))

    recommendations = _build_recommendations(hdr_eval)
    include_hsecscan = _should_include_hsecscan(report_dir, hsecscan_filename)

    present_html = _html_list(present)
    missing_html = _html_list(missing)
    cookies_html = _cookie_flags_html(cookies_flags)
    http_tests_html = _http_tests_html(http_tests)
    recommendations_html = _html_list(recommendations, empty_label="Sin recomendaciones.")

    safe_target_url = escape(str(target_url))
    safe_report_dir = escape(str(report_dir))
    safe_hsecscan_filename = escape(str(hsecscan_filename or ""))
    safe_dalfox_json_filename = escape(str(dalfox_json_filename))
    safe_dalfox_txt_filename = escape(str(dalfox_txt_filename))

    hsecscan_html_section = ""
    if include_hsecscan and hsecscan_filename:
        hsecscan_html_section = f"""
    <section class="card">
      <h2>hsecscan</h2>
      <p>Salida técnica: <code>{safe_hsecscan_filename}</code></p>
      <p class="muted">
        Esta capa complementa la revisión de endurecimiento y exposición visible
        en cabeceras y cookies.
      </p>
    </section>
"""

    expected_artifacts_html = [
        "<li><code>report.md</code></li>",
        "<li><code>report.html</code></li>",
        "<li><code>headers.json</code></li>",
        f"<li><code>{safe_dalfox_json_filename}</code></li>",
        f"<li><code>{safe_dalfox_txt_filename}</code></li>",
        "<li><code>run_meta.json</code></li>",
    ]

    if include_hsecscan and hsecscan_filename:
        expected_artifacts_html.insert(3, f"<li><code>{safe_hsecscan_filename}</code></li>")

    expected_artifacts_html_text = "\n        ".join(expected_artifacts_html)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reporte DASTXH</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background: #f3f4f6;
      color: #111827;
    }}

    .container {{
      width: min(1100px, 92%);
      margin: 2rem auto;
    }}

    .card {{
      background: #ffffff;
      border: 1px solid #d1d5db;
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1rem;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
    }}

    h1, h2, h3 {{
      margin-top: 0;
    }}

    .muted {{
      color: #4b5563;
    }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.75rem;
      margin-top: 1rem;
    }}

    .stat {{
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 0.85rem;
    }}

    code {{
      background: #f3f4f6;
      padding: 0.15rem 0.35rem;
      border-radius: 6px;
    }}

    .cookie-card {{
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 0.85rem;
      margin-bottom: 0.75rem;
    }}

    ul {{
      padding-left: 1.2rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <section class="card">
      <h1>Reporte DASTXH</h1>
      <p><strong>URL objetivo:</strong> {safe_target_url}</p>
      <p><strong>Carpeta del reporte:</strong> <code>{safe_report_dir}</code></p>
    </section>

    <section class="card">
      <h2>Resumen HTTP</h2>

      <div class="stats">
        <div class="stat">
          <strong>Cabeceras evaluadas</strong>
          <div>{headers_evaluadas}</div>
        </div>
        <div class="stat">
          <strong>Cabeceras presentes</strong>
          <div>{headers_presentes}</div>
        </div>
        <div class="stat">
          <strong>Cumplimiento</strong>
          <div>{cumplimiento}%</div>
        </div>
        <div class="stat">
          <strong>Puntaje HTTP</strong>
          <div>{http_score}/100</div>
        </div>
        <div class="stat">
          <strong>Nota HTTP</strong>
          <div>{http_grade}</div>
        </div>
      </div>
    </section>

    <section class="card">
      <h2>Pruebas HTTP detalladas</h2>
      {http_tests_html}
    </section>

    <section class="card">
      <h2>Cabeceras presentes</h2>
      {present_html}

      <h3>Cabeceras faltantes</h3>
      {missing_html}

      <h3>Cookies evaluadas</h3>
      {cookies_html}

      <p class="muted">Evidencia principal: <code>headers.json</code></p>
    </section>

    {hsecscan_html_section}

    <section class="card">
      <h2>Hallazgos XSS (Dalfox)</h2>
      <p>Salida JSON: <code>{safe_dalfox_json_filename}</code></p>
      <p>Salida técnica: <code>{safe_dalfox_txt_filename}</code></p>
      <p class="muted">
        Revisar la salida estructurada y la evidencia técnica para validar hallazgos
        en entornos autorizados.
      </p>
    </section>

    <section class="card">
      <h2>Recomendaciones</h2>
      {recommendations_html}
    </section>

    <section class="card">
      <h2>Archivos generados esperados</h2>
      <ul>
        {expected_artifacts_html_text}
      </ul>
    </section>
  </div>
</body>
</html>"""