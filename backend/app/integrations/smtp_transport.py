import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from typing import Any

from app.core.config import Settings, get_settings


class EmailDeliveryError(Exception):
    """Represent an email delivery failure safe for outbox classification."""

    def __init__(self, code: str, *, transient: bool) -> None:
        super().__init__(code)
        self.code = code
        self.transient = transient


def _response_is_transient(code: int) -> bool:
    return 400 <= code < 500


def _classify_smtp_exception(exc: smtplib.SMTPException) -> EmailDeliveryError:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return EmailDeliveryError("smtp_authentication_failed", transient=False)

    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return EmailDeliveryError("smtp_feature_not_supported", transient=False)

    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        codes = [
            response[0]
            for response in exc.recipients.values()
            if isinstance(response, tuple) and response
        ]
        transient = bool(codes) and all(_response_is_transient(code) for code in codes)
        return EmailDeliveryError("smtp_recipient_rejected", transient=transient)

    if isinstance(exc, smtplib.SMTPResponseException):
        code = exc.smtp_code
        return EmailDeliveryError(
            "smtp_server_rejected_request",
            transient=_response_is_transient(code),
        )

    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return EmailDeliveryError("smtp_server_disconnected", transient=True)

    return EmailDeliveryError("smtp_protocol_error", transient=True)


def send_email(
    message: EmailMessage,
    *,
    settings: Settings | None = None,
    smtp_factory: Callable[..., Any] | None = None,
    smtp_ssl_factory: Callable[..., Any] | None = None,
) -> None:
    """Send a composed email using the configured SMTP transport."""
    config = settings or get_settings()

    host = config.smtp_host.strip()
    sender = config.smtp_from_email.strip()
    username = config.smtp_username
    password = config.smtp_password
    tls_mode = config.smtp_tls_mode

    if not host or not sender:
        raise EmailDeliveryError("smtp_not_configured", transient=False)

    if bool(username) != bool(password):
        raise EmailDeliveryError("smtp_credentials_incomplete", transient=False)

    if username and tls_mode == "none":
        raise EmailDeliveryError("smtp_auth_requires_tls", transient=False)

    if message.get("From") is None or message.get("To") is None:
        raise EmailDeliveryError("email_headers_missing", transient=False)

    context = ssl.create_default_context()

    try:
        if tls_mode == "ssl":
            factory = smtp_ssl_factory or smtplib.SMTP_SSL
            with factory(
                host,
                config.smtp_port,
                timeout=config.smtp_timeout_seconds,
                context=context,
            ) as client:
                _send_with_client(client, message, username, password)
        elif tls_mode in {"starttls", "none"}:
            factory = smtp_factory or smtplib.SMTP
            with factory(
                host,
                config.smtp_port,
                timeout=config.smtp_timeout_seconds,
            ) as client:
                if tls_mode == "starttls":
                    client.ehlo()
                    client.starttls(context=context)
                    client.ehlo()

                _send_with_client(client, message, username, password)
        else:
            raise EmailDeliveryError("smtp_tls_mode_invalid", transient=False)
    except EmailDeliveryError:
        raise
    except smtplib.SMTPException as exc:
        raise _classify_smtp_exception(exc) from exc
    except (TimeoutError, OSError) as exc:
        raise EmailDeliveryError("smtp_connection_failed", transient=True) from exc


def _send_with_client(
    client: Any,
    message: EmailMessage,
    username: str,
    password: str,
) -> None:
    if username:
        client.login(username, password)

    refused = client.send_message(message)
    if refused:
        codes = [
            response[0] for response in refused.values() if isinstance(response, tuple) and response
        ]
        transient = bool(codes) and all(_response_is_transient(code) for code in codes)
        raise EmailDeliveryError("smtp_recipient_rejected", transient=transient)
