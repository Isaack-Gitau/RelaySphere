import pytest

from app.core.origins import parse_allowed_origins


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com", ["https://example.com"]),
        ("HTTPS://EXAMPLE.COM", ["https://example.com"]),
        ("https://example.com:443", ["https://example.com"]),
        ("http://example.com:80", ["http://example.com"]),
        ("http://localhost:5173", ["http://localhost:5173"]),
        (
            "https://example.com, https://api.example.com",
            ["https://example.com", "https://api.example.com"],
        ),
        (
            "https://example.com,https://example.com",
            ["https://example.com"],
        ),
    ],
)
def test_parse_valid_origins(raw: str, expected: list[str]) -> None:
    assert parse_allowed_origins(raw, production=False) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "*",
        "null",
        "ftp://example.com",
        "https://",
        "https://example.com/path",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "https://user@example.com",
        "https://user:password@example.com",
        "https://example.com:",
        "https://example.com:abc",
        "https://example.com:65536",
        "https://example.com:-1",
        "https://[invalid-ipv6]:443",
        "https://bad_.example",
        "https://-bad.example",
        "https://example..com",
        "https://example.com,",
        "https://example.com,,https://api.example.com",
        "https://example .com",
        "https://0x7f000001",
        "https://0177.0.0.1",
        "https://0x7f.0.0.1",
    ],
)
def test_reject_invalid_origins(value: str) -> None:
    with pytest.raises(ValueError):
        parse_allowed_origins(value, production=False)


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com",
        "https://localhost",
        "https://dev.localhost",
        "https://127.0.0.1",
        "https://127.1",
        "https://[::1]",
        "https://0x7f000001",
        "https://0177.0.0.1",
        "https://0x7f.0.0.1",
    ],
)
def test_production_rejects_insecure_or_loopback_origins(value: str) -> None:
    with pytest.raises(ValueError):
        parse_allowed_origins(value, production=True)


def test_production_accepts_public_https_origin() -> None:
    assert parse_allowed_origins(
        "https://app.example.com",
        production=True,
    ) == ["https://app.example.com"]
