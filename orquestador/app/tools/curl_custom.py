"""
curl_custom.py
- CAPA 1: curl custom
- Obtiene headers/cookies y calcula cumplimiento (%).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from config import REQUIRED_HEADERS, UA
from utils import run_cmd


def curl_fetch_headers(url: str, timeout_s: int) -> Tuple[str, Dict[str, Any]]:
    """
    Ejecuta curl y devuelve:
    - raw_last_block: bloque final de headers (considerando redirects)
    - raw_headers_json: status_line + headers parseados + rc/stderr
    """
    cmd = [
        "curl",
        "-sS",
        "-L",
        "--max-time", str(timeout_s),
        "-A", UA,
        "-D", "-",          # headers a stdout
        "-o", "/dev/null",  # body descartado
        url,
    ]
    r = run_cmd(cmd)

    raw = r.out
    blocks = [b for b in re.split(r"\r?\n\r?\n", raw) if b.strip()]

    last = ""
    for b in reversed(blocks):
        if b.strip().startswith("HTTP/"):
            last = b
            break
    if not last:
        last = blocks[-1] if blocks else ""

    headers: Dict[str, Any] = {}
    lines = [ln.strip("\r") for ln in last.splitlines()]
    status_line = lines[0] if lines else ""

    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        lk = k.strip().lower()
        vv = v.strip()

        if lk in headers:
            if isinstance(headers[lk], list):
                headers[lk].append(vv)
            else:
                headers[lk] = [headers[lk], vv]
        else:
            headers[lk] = vv

    raw_headers_json = {
        "status_line": status_line,
        "headers": headers,
        "curl_rc": r.rc,
        "curl_stderr": (r.err or "")[-4000:],
    }

    return last, raw_headers_json


def evaluate_headers_and_cookies(raw_headers_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evalúa:
    - cabeceras presentes/faltantes según REQUIRED_HEADERS
    - flags de cookies: Secure/HttpOnly/SameSite
    - cumplimiento_pct
    """
    headers = raw_headers_json.get("headers", {})

    present: List[str] = []
    missing: List[str] = []
    for h in REQUIRED_HEADERS:
        if h.lower() in headers:
            present.append(h)
        else:
            missing.append(h)

    sc = headers.get("set-cookie")
    cookies = sc if isinstance(sc, list) else ([sc] if sc else [])

    cookies_eval = []
    for c in cookies:
        cl = c.lower()
        cookies_eval.append({
            "cookie": c,
            "secure": "secure" in cl,
            "httponly": "httponly" in cl,
            "samesite": "samesite=" in cl,
        })

    headers_evaluadas = len(REQUIRED_HEADERS)
    headers_presentes = len(present)
    cumplimiento = (headers_presentes / headers_evaluadas * 100.0) if headers_evaluadas else 0.0

    return {
        "headers_evaluadas": headers_evaluadas,
        "headers_presentes": headers_presentes,
        "cumplimiento_pct": round(cumplimiento, 2),
        "present": present,
        "missing": missing,
        "cookies_flags": cookies_eval,
    }