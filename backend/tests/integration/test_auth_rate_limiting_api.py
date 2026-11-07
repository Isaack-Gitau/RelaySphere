from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.services.rate_limiting import RateLimitResult


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session

    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


ROUTE_CASES = [
    pytest.param(
        "/api/v1/auth/register",
        {
            "email": "rate-limit@example.com",
            "display_name": "Rate Limit Test",
            "password": "a-strong-test-password",
            "username": "rate_limit_user",
            "reservation_id": "a1b2c3d4-e5f6-4789-8123-456789abcdef",
            "registration_attempt_id": "550e8400-e29b-41d4-a716-446655440000",
            "reservation_token": "A" * 43,
        },
        [
            ("auth:register:ip", "ip", 5, 3600, "testclient"),
        ],
        id="registration",
    ),
    pytest.param(
        "/api/v1/auth/resend-verification",
        {"email": "rate-limit@example.com"},
        [
            ("auth:resend-verification:ip", "ip", 5, 3600, "testclient"),
            (
                "auth:resend-verification:ip-email",
                "email",
                3,
                3600,
                "testclient\\0rate-limit@example.com",
            ),
        ],
        id="resend-verification",
    ),
    pytest.param(
        "/api/v1/auth/login",
        {"email": "rate-limit@example.com", "password": "incorrect-password"},
        [
            ("auth:login:ip", "ip", 20, 900, "testclient"),
            (
                "auth:login:ip-email",
                "email",
                5,
                900,
                "testclient\\0rate-limit@example.com",
            ),
        ],
        id="login",
    ),
    pytest.param(
        "/api/v1/auth/verify-email",
        {"token": "verification-token"},
        [
            ("auth:verify-email:ip", "ip", 10, 900, "testclient"),
        ],
        id="verify-email",
    ),
    pytest.param(
        "/api/v1/auth/forgot-password",
        {"email": "rate-limit@example.com"},
        [
            ("auth:forgot-password:ip", "ip", 5, 3600, "testclient"),
            (
                "auth:forgot-password:ip-email",
                "email",
                3,
                3600,
                "testclient\\0rate-limit@example.com",
            ),
        ],
        id="forgot-password",
    ),
    pytest.param(
        "/api/v1/auth/reset-password",
        {"token": "reset-token", "new_password": "a-strong-new-password"},
        [
            ("auth:reset-password:ip", "ip", 10, 900, "testclient"),
        ],
        id="reset-password",
    ),
    pytest.param(
        "/api/v1/auth/username-suggestions",
        {"display_name": "Isaack Gitau"},
        [
            ("auth:username-suggestions:ip", "ip", 30, 3600, "testclient"),
        ],
        id="username-suggestions",
    ),
]


@pytest.mark.parametrize(("path", "payload", "expected_buckets"), ROUTE_CASES)
def test_auth_endpoints_return_429_when_rate_limited(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    payload: dict[str, str],
    expected_buckets: list[tuple[str, str, int, int, str]],
) -> None:
    observed: dict[str, object] = {}

    def deny_request(_buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = _buckets
        return RateLimitResult(allowed=False, retry_after_seconds=37)

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.consume_rate_limit_buckets",
        deny_request,
    )

    response = api_client.post(path, json=payload)

    assert response.status_code == 429
    assert response.json() == {"detail": "Too many requests. Please try again later."}
    assert response.headers["retry-after"] == "37"

    actual_buckets = observed["buckets"]
    assert isinstance(actual_buckets, list)
    assert [
        (
            bucket.scope,
            bucket.kind,
            bucket.limit,
            bucket.window_seconds,
            bucket.identifier,
        )
        for bucket in actual_buckets
    ] == expected_buckets


@pytest.mark.parametrize(("path", "payload", "_expected_buckets"), ROUTE_CASES)
def test_auth_endpoints_fail_closed_when_rate_limit_database_fails(
    api_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    payload: dict[str, str],
    _expected_buckets: list[tuple[str, str, int, int, str]],
) -> None:
    def fail_rate_limiter(_buckets: list[object]) -> RateLimitResult:
        raise SQLAlchemyError("simulated rate-limit database failure")

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.consume_rate_limit_buckets",
        fail_rate_limiter,
    )

    response = api_client.post(path, json=payload)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
