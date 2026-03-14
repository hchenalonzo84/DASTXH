from __future__ import annotations

from pathlib import Path
from typing import List


def list_report_directories(reports_root: Path) -> List[str]:
    if not reports_root.exists():
        return []

    return sorted(
        [p.name for p in reports_root.iterdir() if p.is_dir()],
        reverse=True,
    )