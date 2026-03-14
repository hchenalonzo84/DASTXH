"""
report.py
- Construcción de reportes legibles para DASTXH.
- En esta etapa genera:
  * report.md
  * report.html
- Más adelante, report.html podrá servir como base para generar report.pdf.

El objetivo es centralizar la presentación de resultados:
- Capa 1: Security Headers (curl custom)
- Capa 2: Hardening & Cookies (hsecscan)
- Capa 3: XSS Findings (Dalfox)
- Conclusión y recomendaciones
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, List


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _to_list(value: Any) -> List[Any]:
    """
    Normaliza un valor a lista.

    Casos:
    - None -> []
    - lista -> la misma lista
    - cualquier otro valor -> [valor]
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _md_bullets(items: List[str], empty_label: str = "- (none)") -> str:
    """
    Convierte una lista de strings en una lista Markdown.

    Si no hay elementos, devuelve una etiqueta por defecto.
    """
    if not items:
        return empty_label
    return "\n".join(f"- {item}" for item in items)


def _html_list(items: List[str], empty_label: str = "(none)") -> str:
    """
    Convierte una lista de strings en una lista HTML <ul>.

    Si no hay elementos, devuelve un párrafo simple.
    """
    if not items:
        return f"<p>{escape(empty_label)}</p>"

    rows = "\n".join(f"<li>{escape(str(item))}</li>" for item in items)
    return f"<ul>\n{rows}\n</ul>"


def _cookie_flags_md(cookies_flags: List[Dict[str, Any]]) -> str:
    """
    Genera una sección Markdown resumida para las cookies evaluadas.

    Cada cookie se muestra con sus flags:
    - Secure
    - HttpOnly
    - SameSite
    """
    if not cookies_flags:
        return "- No se detectaron cookies Set-Cookie en la respuesta final."

    lines: List[str] = []
    for item in cookies_flags:
        cookie_value = str(item.get("cookie", ""))
        secure = "Yes" if item.get("secure") else "No"
        httponly = "Yes" if item.get("httponly") else "No"
        samesite = "Yes" if item.get("samesite") else "No"

        lines.append(f"- Cookie: `{cookie_value}`")
        lines.append(f"  - Secure: **{secure}**")
        lines.append(f"  - HttpOnly: **{httponly}**")
        lines.append(f"  - SameSite: **{samesite}**")

    return "\n".join(lines)


def _cookie_flags_html(cookies_flags: List[Dict[str, Any]]) -> str:
    """
    Genera una sección HTML resumida para las cookies evaluadas.
    """
    if not cookies_flags:
        return "<p>No se detectaron cookies <code>Set-Cookie</code> en la respuesta final.</p>"

    blocks: List[str] = []
    for item in cookies_flags:
        cookie_value = escape(str(item.get("cookie", "")))
        secure = "Yes" if item.get("secure") else "No"
        httponly = "Yes" if item.get("httponly") else "No"
        samesite = "Yes" if item.get("samesite") else "No"

        block = f"""
        <div class="cookie-card">
          <p><strong>Cookie:</strong> <code>{cookie_value}</code></p>
          <ul>
            <li><strong>Secure:</strong> {secure}</li>
            <li><strong>HttpOnly:</strong> {httponly}</li>
            <li><strong>SameSite:</strong> {samesite}</li>
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
    cookies_flags = _to_list(hdr_eval.get("cookies_flags"))

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

    if any(not c.get("samesite") for c in cookies_flags):
        recommendations.append(
            "Definir SameSite en cookies sensibles para reducir exposición ante ciertos escenarios de ataque."
        )

    if not recommendations:
        recommendations.append(
            "Mantener las configuraciones actuales y validar periódicamente la exposición de cabeceras y cookies."
        )

    recommendations.append(
        "Si Dalfox reporta hallazgos XSS, validar únicamente en entornos autorizados y corregir sanitización/encoding."
    )

    return recommendations


# ==========================================================
# REPORTE MARKDOWN
# ==========================================================

def build_report_md(
    target_url: str,
    report_dir: Path,
    hdr_eval: Dict[str, Any],
    hsecscan_filename: str,
    dalfox_json_filename: str,
    dalfox_txt_filename: str = "dalfox.txt",
) -> str:
    """
    Construye el contenido del reporte principal en formato Markdown.

    Parámetros:
    - target_url: URL evaluada
    - report_dir: carpeta física donde quedaron los artifacts
    - hdr_eval: resumen de evaluación de la capa 1
    - hsecscan_filename: nombre del archivo raw de hsecscan
    - dalfox_json_filename: nombre del archivo JSON de Dalfox
    - dalfox_txt_filename: nombre del archivo raw de Dalfox
    """
    headers_evaluadas = hdr_eval.get("headers_evaluadas", 0)
    headers_presentes = hdr_eval.get("headers_presentes", 0)
    cumplimiento = hdr_eval.get("cumplimiento_pct", 0)

    present = _to_list(hdr_eval.get("present"))
    missing = _to_list(hdr_eval.get("missing"))
    cookies_flags = _to_list(hdr_eval.get("cookies_flags"))

    present_md = _md_bullets([str(x) for x in present])
    missing_md = _md_bullets([str(x) for x in missing])
    cookies_md = _cookie_flags_md(cookies_flags)

    recommendations = _build_recommendations(hdr_eval)
    recommendations_md = _md_bullets(recommendations)

    return f"""# DASTXH Report

**Target:** {target_url}  
**Report folder:** `{report_dir}`

---

## A) Security Headers (custom)

- Headers evaluadas: **{headers_evaluadas}**
- Headers presentes: **{headers_presentes}**
- Cumplimiento: **{cumplimiento}%**

### Present
{present_md}

### Missing
{missing_md}

### Cookies flags
{cookies_md}

> Evidencia principal: `headers.json`

---

## B) Hardening & Cookies (hsecscan, segunda capa)

Salida raw: `{hsecscan_filename}`

> Esta capa complementa la revisión de endurecimiento y exposición visible en cabeceras/cookies.

---

## C) XSS Findings (Dalfox)

Salida JSON: `{dalfox_json_filename}`  
Salida raw: `{dalfox_txt_filename}`

> Revisar la salida estructurada y la evidencia raw para validar hallazgos en entornos autorizados.

---

## D) Recomendaciones

{recommendations_md}

---

## E) Artifacts generados esperados

- `report.md`
- `report.html`
- `headers.json`
- `{hsecscan_filename}`
- `{dalfox_json_filename}`
- `{dalfox_txt_filename}`
- `run_meta.json`
"""
    

# ==========================================================
# REPORTE HTML
# ==========================================================

def build_report_html(
    target_url: str,
    report_dir: Path,
    hdr_eval: Dict[str, Any],
    hsecscan_filename: str,
    dalfox_json_filename: str,
    dalfox_txt_filename: str = "dalfox.txt",
) -> str:
    """
    Construye el contenido del reporte en HTML.

    Este HTML está pensado para:
    - abrirse directamente desde la GUI web
    - servir como base futura para exportación a PDF
    """
    headers_evaluadas = hdr_eval.get("headers_evaluadas", 0)
    headers_presentes = hdr_eval.get("headers_presentes", 0)
    cumplimiento = hdr_eval.get("cumplimiento_pct", 0)

    present = [str(x) for x in _to_list(hdr_eval.get("present"))]
    missing = [str(x) for x in _to_list(hdr_eval.get("missing"))]
    cookies_flags = _to_list(hdr_eval.get("cookies_flags"))

    recommendations = _build_recommendations(hdr_eval)

    present_html = _html_list(present)
    missing_html = _html_list(missing)
    cookies_html = _cookie_flags_html(cookies_flags)
    recommendations_html = _html_list(recommendations, empty_label="No recommendations.")

    safe_target_url = escape(str(target_url))
    safe_report_dir = escape(str(report_dir))
    safe_hsecscan_filename = escape(str(hsecscan_filename))
    safe_dalfox_json_filename = escape(str(dalfox_json_filename))
    safe_dalfox_txt_filename = escape(str(dalfox_txt_filename))

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DASTXH Report</title>
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
      <h1>DASTXH Report</h1>
      <p><strong>Target:</strong> {safe_target_url}</p>
      <p><strong>Report folder:</strong> <code>{safe_report_dir}</code></p>
    </section>

    <section class="card">
      <h2>A) Security Headers (custom)</h2>

      <div class="stats">
        <div class="stat">
          <strong>Headers evaluadas</strong>
          <div>{headers_evaluadas}</div>
        </div>
        <div class="stat">
          <strong>Headers presentes</strong>
          <div>{headers_presentes}</div>
        </div>
        <div class="stat">
          <strong>Cumplimiento</strong>
          <div>{cumplimiento}%</div>
        </div>
      </div>

      <h3>Present</h3>
      {present_html}

      <h3>Missing</h3>
      {missing_html}

      <h3>Cookies flags</h3>
      {cookies_html}

      <p class="muted">Evidencia principal: <code>headers.json</code></p>
    </section>

    <section class="card">
      <h2>B) Hardening & Cookies (hsecscan, segunda capa)</h2>
      <p>Salida raw: <code>{safe_hsecscan_filename}</code></p>
      <p class="muted">
        Esta capa complementa la revisión de endurecimiento y exposición visible
        en cabeceras/cookies.
      </p>
    </section>

    <section class="card">
      <h2>C) XSS Findings (Dalfox)</h2>
      <p>Salida JSON: <code>{safe_dalfox_json_filename}</code></p>
      <p>Salida raw: <code>{safe_dalfox_txt_filename}</code></p>
      <p class="muted">
        Revisar la salida estructurada y la evidencia raw para validar hallazgos
        en entornos autorizados.
      </p>
    </section>

    <section class="card">
      <h2>D) Recomendaciones</h2>
      {recommendations_html}
    </section>

    <section class="card">
      <h2>E) Artifacts generados esperados</h2>
      <ul>
        <li><code>report.md</code></li>
        <li><code>report.html</code></li>
        <li><code>headers.json</code></li>
        <li><code>{safe_hsecscan_filename}</code></li>
        <li><code>{safe_dalfox_json_filename}</code></li>
        <li><code>{safe_dalfox_txt_filename}</code></li>
        <li><code>run_meta.json</code></li>
      </ul>
    </section>
  </div>
</body>
</html>
"""