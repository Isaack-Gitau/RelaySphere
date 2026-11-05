from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest

from app.integrations.email_messages import (
    EMAIL_CHANGE_EMAIL_SUBJECT,
    VERIFICATION_EMAIL_SUBJECT,
    build_email_change_url,
    build_verification_url,
    compose_email_change_email,
    compose_verification_email,
)


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.extend(value for key, value in attrs if key == "href" and value is not None)


def test_build_verification_url_encodes_token_and_preserves_query() -> None:
    result = build_verification_url(
        "https://app.example.test/verify-email?source=signup",
        "token+/with=special",
    )

    parsed = urlsplit(result)

    assert parsed.scheme == "https"
    assert parsed.netloc == "app.example.test"
    assert parsed.path == "/verify-email"
    assert parse_qs(parsed.query) == {
        "source": ["signup"],
        "token": ["token+/with=special"],
    }


def test_build_verification_url_replaces_existing_token() -> None:
    result = build_verification_url(
        "https://app.example.test/verify-email?token=old",
        "new-token",
    )

    assert parse_qs(urlsplit(result).query)["token"] == ["new-token"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "/verify-email",
        "ftp://app.example.test/verify-email",
        "https://user:password@app.example.test/verify-email",
        "https://app.example.test/verify-email#fragment",
    ],
)
def test_build_verification_url_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        build_verification_url(url, "test-token")


def test_build_verification_url_rejects_empty_token() -> None:
    with pytest.raises(ValueError):
        build_verification_url("https://app.example.test/verify-email", "")


def test_compose_verification_email_has_plain_text_and_html_parts() -> None:
    message = compose_verification_email(
        recipient_email="person@example.test",
        display_name="RelaySphere User",
        raw_token="test-token",
        verification_url="https://app.example.test/verify-email",
        sender_email="noreply@example.test",
    )

    assert isinstance(message, EmailMessage)
    assert message["To"] == "person@example.test"
    assert message["Subject"] == VERIFICATION_EMAIL_SUBJECT
    assert message.get_content_type() == "multipart/alternative"

    parts = list(message.iter_parts())
    assert len(parts) == 2
    assert parts[0].get_content_type() == "text/plain"
    assert parts[1].get_content_type() == "text/html"

    assert "Hello RelaySphere User" in parts[0].get_content()
    assert "24 hours" in parts[0].get_content()
    assert "test-token" in parts[0].get_content()


def test_html_content_escapes_display_name_and_uses_verification_link() -> None:
    message = compose_verification_email(
        recipient_email="person@example.test",
        display_name="<script>alert(1)</script>",
        raw_token="test-token",
        verification_url="https://app.example.test/verify-email",
        sender_email="noreply@example.test",
    )

    html_part = list(message.iter_parts())[1].get_content()

    assert "<script>" not in html_part
    assert "&lt;script&gt;" in html_part

    parser = LinkParser()
    parser.feed(html_part)

    assert len(parser.links) == 1
    assert parse_qs(urlsplit(parser.links[0]).query)["token"] == ["test-token"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recipient_email", ""),
        ("sender_email", ""),
        ("display_name", ""),
    ],
)
def test_compose_verification_email_rejects_missing_required_fields(
    field: str,
    value: str,
) -> None:
    arguments = {
        "recipient_email": "person@example.test",
        "display_name": "RelaySphere User",
        "raw_token": "test-token",
        "verification_url": "https://app.example.test/verify-email",
        "sender_email": "noreply@example.test",
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        compose_verification_email(**arguments)

def test_build_email_change_url_encodes_token_and_preserves_query() -> None:
    result = build_email_change_url(
        "https://app.example.test/confirm-email-change?source=settings",
        "token+/with=special",
    )

    parsed = urlsplit(result)

    assert parsed.scheme == "https"
    assert parsed.netloc == "app.example.test"
    assert parsed.path == "/confirm-email-change"
    assert parse_qs(parsed.query) == {
        "source": ["settings"],
        "token": ["token+/with=special"],
    }


def test_build_email_change_url_replaces_existing_token() -> None:
    result = build_email_change_url(
        "https://app.example.test/confirm-email-change?token=old",
        "new-token",
    )

    assert parse_qs(urlsplit(result).query)["token"] == ["new-token"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "/confirm-email-change",
        "ftp://app.example.test/confirm-email-change",
        "https://user:password@app.example.test/confirm-email-change",
        "https://app.example.test/confirm-email-change#fragment",
    ],
)
def test_build_email_change_url_rejects_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        build_email_change_url(url, "test-token")


def test_build_email_change_url_rejects_empty_token() -> None:
    with pytest.raises(ValueError):
        build_email_change_url(
            "https://app.example.test/confirm-email-change",
            "",
        )


def test_compose_email_change_email_has_plain_text_and_html_parts() -> None:
    message = compose_email_change_email(
        recipient_email="new-address@example.test",
        display_name="RelaySphere User",
        raw_token="test-email-change-token",
        confirmation_url="https://app.example.test/confirm-email-change",
        sender_email="noreply@example.test",
    )

    assert isinstance(message, EmailMessage)
    assert message["To"] == "new-address@example.test"
    assert message["Subject"] == EMAIL_CHANGE_EMAIL_SUBJECT
    assert message.get_content_type() == "multipart/alternative"

    parts = list(message.iter_parts())
    assert len(parts) == 2
    assert parts[0].get_content_type() == "text/plain"
    assert parts[1].get_content_type() == "text/html"

    plain_text = parts[0].get_content()
    assert "Hello RelaySphere User" in plain_text
    assert "24 hours" in plain_text
    assert "used only once" in plain_text
    assert "current email address will remain unchanged" in plain_text
    assert (
        "https://app.example.test/confirm-email-change"
        "?token=test-email-change-token"
    ) in plain_text


def test_email_change_html_escapes_display_name_and_uses_confirmation_link() -> None:
    message = compose_email_change_email(
        recipient_email="new-address@example.test",
        display_name="<script>alert(1)</script>",
        raw_token="test-token",
        confirmation_url="https://app.example.test/confirm-email-change",
        sender_email="noreply@example.test",
    )

    html_part = list(message.iter_parts())[1].get_content()

    assert "<script>" not in html_part
    assert "&lt;script&gt;" in html_part

    parser = LinkParser()
    parser.feed(html_part)

    assert len(parser.links) == 1
    assert parse_qs(urlsplit(parser.links[0]).query)["token"] == ["test-token"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recipient_email", ""),
        ("sender_email", ""),
        ("display_name", ""),
    ],
)
def test_compose_email_change_email_rejects_missing_required_fields(
    field: str,
    value: str,
) -> None:
    arguments = {
        "recipient_email": "new-address@example.test",
        "display_name": "RelaySphere User",
        "raw_token": "test-token",
        "confirmation_url": "https://app.example.test/confirm-email-change",
        "sender_email": "noreply@example.test",
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        compose_email_change_email(**arguments)
