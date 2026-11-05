from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest

from app.core.password_reset import PASSWORD_RESET_TOKEN_EXPIRY_MINUTES
from app.integrations.email_messages import (
    PASSWORD_RESET_EMAIL_SUBJECT,
    build_password_reset_url,
    build_verification_url,
    compose_password_reset_email,
)

RESET_URL = "https://app.example.test/reset-password"


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.extend(value for key, value in attrs if key == "href" and value is not None)


def compose(**overrides: str) -> EmailMessage:
    arguments = {
        "recipient_email": "person@example.test",
        "display_name": "RelaySphere User",
        "raw_token": "test-token",
        "reset_url": RESET_URL,
        "sender_email": "noreply@example.test",
    }
    arguments.update(overrides)
    return compose_password_reset_email(**arguments)


def test_build_password_reset_url_encodes_token_and_preserves_query() -> None:
    result = build_password_reset_url(
        "https://app.example.test/reset-password?source=email",
        "token+/with=special",
    )

    parsed = urlsplit(result)

    assert parsed.scheme == "https"
    assert parsed.netloc == "app.example.test"
    assert parsed.path == "/reset-password"
    assert parse_qs(parsed.query) == {
        "source": ["email"],
        "token": ["token+/with=special"],
    }


def test_build_password_reset_url_replaces_existing_token() -> None:
    result = build_password_reset_url(
        "https://app.example.test/reset-password?token=old",
        "new-token",
    )

    assert parse_qs(urlsplit(result).query)["token"] == ["new-token"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "/reset-password",
        "ftp://app.example.test/reset-password",
        "https://user:password@app.example.test/reset-password",
        "https://app.example.test/reset-password#fragment",
    ],
)
def test_build_password_reset_url_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        build_password_reset_url(url, "test-token")


def test_build_password_reset_url_rejects_empty_token() -> None:
    with pytest.raises(ValueError):
        build_password_reset_url(RESET_URL, "")


def test_password_reset_url_errors_name_the_password_reset_flow() -> None:
    with pytest.raises(ValueError, match="password reset token is required"):
        build_password_reset_url(RESET_URL, "")

    with pytest.raises(ValueError, match="password reset URL must be an absolute"):
        build_password_reset_url("/reset-password", "test-token")


def test_verification_url_errors_still_name_the_verification_flow() -> None:
    with pytest.raises(ValueError, match="verification token is required"):
        build_verification_url("https://app.example.test/verify-email", "")

    with pytest.raises(ValueError, match="verification URL must be an absolute"):
        build_verification_url("/verify-email", "test-token")


def test_password_reset_subject_constant() -> None:
    assert PASSWORD_RESET_EMAIL_SUBJECT == "Reset your RelaySphere password"


def test_compose_password_reset_email_has_plain_text_and_html_parts() -> None:
    message = compose()

    assert isinstance(message, EmailMessage)
    assert message["To"] == "person@example.test"
    assert message["Subject"] == PASSWORD_RESET_EMAIL_SUBJECT
    assert "test-token" not in message["Subject"]
    assert message.get_content_type() == "multipart/alternative"

    parts = list(message.iter_parts())
    assert len(parts) == 2
    assert parts[0].get_content_type() == "text/plain"
    assert parts[1].get_content_type() == "text/html"

    text = parts[0].get_content()
    assert "Hello RelaySphere User" in text
    assert "test-token" in text
    assert "you can ignore this email" in text


def test_password_reset_email_states_the_real_expiry() -> None:
    message = compose()

    parts = list(message.iter_parts())
    expected = f"{PASSWORD_RESET_TOKEN_EXPIRY_MINUTES} minutes"

    assert expected in parts[0].get_content()
    assert expected in parts[1].get_content()


def test_html_content_escapes_display_name_and_uses_reset_link() -> None:
    message = compose(display_name="<script>alert(1)</script>")

    html_part = list(message.iter_parts())[1].get_content()

    assert "<script>" not in html_part
    assert "&lt;script&gt;" in html_part

    parser = LinkParser()
    parser.feed(html_part)

    assert len(parser.links) == 1
    link = urlsplit(parser.links[0])
    assert link.path == "/reset-password"
    assert parse_qs(link.query)["token"] == ["test-token"]


@pytest.mark.parametrize(
    "field",
    ["recipient_email", "sender_email", "display_name"],
)
def test_compose_password_reset_email_rejects_missing_required_fields(field: str) -> None:
    with pytest.raises(ValueError):
        compose(**{field: ""})
