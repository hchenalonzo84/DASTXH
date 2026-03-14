from fastapi import APIRouter

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/health")
def scans_health() -> dict:
    return {"module": "scans", "ok": True}