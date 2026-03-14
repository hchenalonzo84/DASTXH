from fastapi import APIRouter

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("/health")
def history_health() -> dict:
    return {"module": "history", "ok": True}