"""
dalfox_tool.py
- CAPA 3: Dalfox (XSS)
- Ejecuta: dalfox url <target> --format json -o dalfox.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Tuple

from config import UA
from utils import run_cmd


def run_dalfox(url: str, timeout_s: int, out_json: Path) -> Tuple[int, str]:
    cmd = [
        "dalfox", "url", url,
        "--no-color",
        "--no-spinner",
        "--format", "json",
        "-o", str(out_json),
        "--timeout", str(timeout_s),
        "--user-agent", UA,
        "-F",
    ]
    r = run_cmd(cmd)
    raw = (r.out or "") + ("\n" + r.err if r.err else "")
    return r.rc, raw


def read_summary(out_json: Path) -> tuple[int, Any]:
    if not out_json.exists():
        return 0, {"_no_json": True}

    try:
        data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0, {"_parse_error": True}

    findings = 0
    if isinstance(data, list):
        findings = len(data)
    elif isinstance(data, dict):
        for k in ("issues", "found", "results", "vulnerabilities"):
            v = data.get(k)
            if isinstance(v, list):
                findings = len(v)
                break

    return findings, data