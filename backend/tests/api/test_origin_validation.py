import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

AUTH_PATH = "/api/v1/auth/__origin_test__"
TRUSTED_ORIGIN = "http://localhost:5173"
UNTRUSTED_ORIGIN = "https://attacker.example"


def test_auth_post_rejects_missing_origin() -> None:
    response = client.post(AUTH_PATH)

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}


def test_auth_post_rejects_untrusted_origin() -> None:
    response = client.post(
        AUTH_PATH,
        headers={"Origin": UNTRUSTED_ORIGIN},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}


def test_auth_post_with_trusted_origin_reaches_application() -> None:
    response = client.post(
        AUTH_PATH,
        headers={"Origin": TRUSTED_ORIGIN},
    )

    # The route does not exist; 404 proves the origin guard allowed it through.
    assert response.status_code == 404


def test_auth_post_rejects_duplicate_origin_headers() -> None:
    response = client.post(
        AUTH_PATH,
        headers=[
            ("Origin", TRUSTED_ORIGIN),
            ("Origin", UNTRUSTED_ORIGIN),
        ],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}


def test_cors_preflight_allows_trusted_origin() -> None:
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": TRUSTED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == TRUSTED_ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert "POST" in response.headers["access-control-allow-methods"]


def test_cors_preflight_does_not_allow_untrusted_origin() -> None:
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_get_auth_route_is_not_blocked_by_origin_guard() -> None:
    response = client.get(
        AUTH_PATH,
        headers={"Origin": UNTRUSTED_ORIGIN},
    )

    # The request reaches routing; the Origin guard only checks POST requests.
    assert response.status_code == 404


def test_non_auth_post_is_not_blocked_by_origin_guard() -> None:
    response = client.post(
        "/api/v1/health",
        headers={"Origin": UNTRUSTED_ORIGIN},
    )

    # The health endpoint only supports GET, so FastAPI returns 405.
    assert response.status_code == 405


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_auth_methods_reject_untrusted_origin(method: str) -> None:
    response = client.request(
        method,
        AUTH_PATH,
        headers={"Origin": UNTRUSTED_ORIGIN},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Untrusted request origin."}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_auth_methods_allow_trusted_origin(method: str) -> None:
    response = client.request(
        method,
        AUTH_PATH,
        headers={"Origin": TRUSTED_ORIGIN},
    )

    # The route does not exist; 404 proves the origin guard allowed it through.
    assert response.status_code == 404
