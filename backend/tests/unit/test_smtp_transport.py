import smtplib
from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from app.integrations.smtp_transport import EmailDeliveryError, send_email


def make_settings(**overrides):
    values = {
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_username": "relay@example.test",
        "smtp_password": "test-password",
        "smtp_from_email": "noreply@example.test",
        "smtp_tls_mode": "starttls",
        "smtp_timeout_seconds": 10.0,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def make_message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "noreply@example.test"
    message["To"] = "person@example.test"
    message["Subject"] = "Test"
    message.set_content("Test message")
    return message


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.calls = []
        self.refused = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, **kwargs):
        self.calls.append(("starttls", kwargs))

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def send_message(self, message):
        self.calls.append(("send_message", message))
        return self.refused


def test_starttls_connection_authenticates_and_sends() -> None:
    clients = []

    def factory(*args, **kwargs):
        client = FakeSMTP(*args, **kwargs)
        clients.append(client)
        return client

    send_email(
        make_message(),
        settings=make_settings(),
        smtp_factory=factory,
    )

    client = clients[0]
    assert client.args == ("smtp.example.test", 587)
    assert client.kwargs["timeout"] == 10.0
    assert [call[0] for call in client.calls] == [
        "ehlo",
        "starttls",
        "ehlo",
        "login",
        "send_message",
    ]


def test_ssl_connection_uses_ssl_factory() -> None:
    clients = []

    def factory(*args, **kwargs):
        client = FakeSMTP(*args, **kwargs)
        clients.append(client)
        return client

    send_email(
        make_message(),
        settings=make_settings(smtp_tls_mode="ssl", smtp_port=465),
        smtp_ssl_factory=factory,
    )

    assert clients[0].args == ("smtp.example.test", 465)
    assert clients[0].kwargs["context"] is not None
    assert [call[0] for call in clients[0].calls] == ["login", "send_message"]


def test_authentication_is_skipped_when_credentials_are_absent() -> None:
    clients = []

    def factory(*args, **kwargs):
        client = FakeSMTP(*args, **kwargs)
        clients.append(client)
        return client

    send_email(
        make_message(),
        settings=make_settings(
            smtp_username="",
            smtp_password="",
            smtp_tls_mode="none",
        ),
        smtp_factory=factory,
    )

    assert [call[0] for call in clients[0].calls] == ["send_message"]


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"smtp_host": ""}, "smtp_not_configured"),
        ({"smtp_from_email": ""}, "smtp_not_configured"),
        (
            {"smtp_username": "relay@example.test", "smtp_password": ""},
            "smtp_credentials_incomplete",
        ),
        ({"smtp_username": "", "smtp_password": "secret"}, "smtp_credentials_incomplete"),
        ({"smtp_tls_mode": "none"}, "smtp_auth_requires_tls"),
    ],
)
def test_invalid_configuration_is_permanent(
    overrides: dict,
    expected_code: str,
) -> None:
    with pytest.raises(EmailDeliveryError) as error:
        send_email(make_message(), settings=make_settings(**overrides))

    assert error.value.code == expected_code
    assert error.value.transient is False


def test_missing_message_headers_are_rejected() -> None:
    with pytest.raises(EmailDeliveryError) as error:
        send_email(EmailMessage(), settings=make_settings())

    assert error.value.code == "email_headers_missing"
    assert error.value.transient is False


def test_authentication_failure_is_permanent() -> None:
    class AuthenticationFailure(FakeSMTP):
        def login(self, username, password):
            raise smtplib.SMTPAuthenticationError(535, b"Authentication failed")

    with pytest.raises(EmailDeliveryError) as error:
        send_email(
            make_message(),
            settings=make_settings(),
            smtp_factory=AuthenticationFailure,
        )

    assert error.value.code == "smtp_authentication_failed"
    assert error.value.transient is False


@pytest.mark.parametrize(
    ("code", "transient"),
    [(421, True), (450, True), (550, False), (554, False)],
)
def test_smtp_response_errors_are_classified(code: int, transient: bool) -> None:
    class RejectedRequest(FakeSMTP):
        def send_message(self, message):
            raise smtplib.SMTPDataError(code, b"Rejected")

    with pytest.raises(EmailDeliveryError) as error:
        send_email(
            make_message(),
            settings=make_settings(),
            smtp_factory=RejectedRequest,
        )

    assert error.value.code == "smtp_server_rejected_request"
    assert error.value.transient is transient


def test_connection_error_is_transient() -> None:
    def factory(*args, **kwargs):
        raise TimeoutError("connection timed out")

    with pytest.raises(EmailDeliveryError) as error:
        send_email(
            make_message(),
            settings=make_settings(),
            smtp_factory=factory,
        )

    assert error.value.code == "smtp_connection_failed"
    assert error.value.transient is True


def test_refused_recipient_is_classified() -> None:
    class RefusedRecipient(FakeSMTP):
        def send_message(self, message):
            return {"person@example.test": (450, b"Try again")}

    with pytest.raises(EmailDeliveryError) as error:
        send_email(
            make_message(),
            settings=make_settings(),
            smtp_factory=RefusedRecipient,
        )

    assert error.value.code == "smtp_recipient_rejected"
    assert error.value.transient is True
