from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


def get_reports_root() -> Path:
    return Path("/work/reports")


@router.get("/health")
def reports_health() -> dict:
    return {"module": "reports", "ok": True}


@router.get("/file/{run_id}/{filename:path}")
def get_report_file(run_id: str, filename: str):
    base = get_reports_root() / run_id
    file_path = (base / filename).resolve()

    try:
        file_path.relative_to(base.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Ruta inválida.")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado.")

    return FileResponse(file_path)