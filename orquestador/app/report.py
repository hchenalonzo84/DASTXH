"""
report.py
- Construye el reporte unificado report.md:
  A) Security Headers (custom)
  B) Hardening & Cookies (hsecscan)
  C) XSS Findings (Dalfox)
  + Conclusión
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


def build_report_md(
    target_url: str,
    report_dir: Path,
    hdr_eval: Dict[str, Any],
    hsecscan_filename: str,
    dalfox_json_filename: str,
) -> str:
    """
    Devuelve el contenido completo del reporte en formato Markdown.
    """
    present = hdr_eval.get("present", [])
    missing = hdr_eval.get("missing", [])
    cumplimiento = hdr_eval.get("cumplimiento_pct", 0)

    present_md = "\n".join([f"- {h}" for h in present]) if present else "- (none)"
    missing_md = "\n".join([f"- {h}" for h in missing]) if missing else "- (none)"

    return f"""# DASTXH Report

**Target:** {target_url}  
**Report folder:** `{report_dir}`

---

## A) Security Headers (custom)

- Headers evaluadas: **{hdr_eval.get("headers_evaluadas")}**
- Headers presentes: **{hdr_eval.get("headers_presentes")}**
- Cumplimiento: **{cumplimiento}%**

### Present
{present_md}

### Missing
{missing_md}

> Evidencia: `headers.json`

---

## B) Hardening & Cookies (hsecscan, segunda capa)

Salida (raw): `{hsecscan_filename}`

---

## C) XSS Findings (Dalfox)

Salida JSON: `{dalfox_json_filename}`  
Salida raw: `dalfox.txt`

---

## Conclusión (resumen + recomendaciones)

- Agrega cabeceras faltantes (CSP/HSTS/etc.) según el contexto.
- Asegura cookies con **Secure + HttpOnly + SameSite** donde aplique.
- Si hay hallazgos XSS, valida en laboratorio/autorizado y corrige sanitización/encoding.

"""