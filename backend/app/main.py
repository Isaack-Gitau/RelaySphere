from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.endpoints.auth import router as auth_router
from app.core.config import get_settings
from app.db.session import get_engine

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="API for the RelaySphere real-time messaging platform.",
    version=settings.app_version,
)

app.include_router(auth_router, prefix=settings.api_v1_prefix)


@app.get("/api/v1/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Confirm that the API process is responding."""
    return {"status": "ok"}


@app.get(
    "/api/v1/ready",
    tags=["Health"],
    response_model=None,
)
async def readiness_check() -> dict[str, str] | JSONResponse:
    """Check whether the API can reach its required database."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, RuntimeError):
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "database": "unavailable",
            },
        )

    return {"status": "ready", "database": "available"}
