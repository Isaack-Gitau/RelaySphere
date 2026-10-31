from types import SimpleNamespace

import pytest

from app.api.v1.endpoints import auth


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        ("/api/v1", "/api/v1/auth"),
        ("/api/v2", "/api/v2/auth"),
        ("/custom/api/", "/custom/api/auth"),
    ],
)
def test_auth_cookie_path_uses_configured_api_prefix(
    monkeypatch: pytest.MonkeyPatch,
    prefix: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(api_v1_prefix=prefix),
    )

    assert auth._auth_cookie_path() == expected
