from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.user_blocks import router as user_blocks_router
from app.api.v1.endpoints.user_discovery import router as user_discovery_router
from app.api.v1.endpoints.users import router as users_router
from app.core.config import get_settings
from app.core.origins import parse_allowed_origins
from app.db.session import get_engine
from app.middleware.origin_validation import OriginValidationMiddleware
from app.security.csrf import validate_csrf_secret
from app.security.rate_limit import validate_rate_limit_secret
from app.security.tokens import validate_access_token_secret

settings = get_settings()
validate_access_token_secret(settings.access_token_secret)
validate_csrf_secret(settings.csrf_secret)
validate_rate_limit_secret(settings.rate_limit_secret)

app = FastAPI(
    title=settings.app_name,
    description="API for the RelaySphere real-time messaging platform.",
    version=settings.app_version,
)

is_production = settings.environment.lower() not in {"development", "testing"}

try:
    allowed_origins = parse_allowed_origins(
        settings.cors_allowed_origins,
        production=is_production,
    )
except ValueError as exc:
    raise RuntimeError(str(exc)) from exc

app.add_middleware(
    OriginValidationMiddleware,
    allowed_origins=allowed_origins,
    auth_prefix=f"{settings.api_v1_prefix.rstrip('/')}/auth",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    expose_headers=[],
)

app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(users_router, prefix=settings.api_v1_prefix)
app.include_router(user_blocks_router, prefix=settings.api_v1_prefix)
app.include_router(user_discovery_router, prefix=settings.api_v1_prefix)


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
