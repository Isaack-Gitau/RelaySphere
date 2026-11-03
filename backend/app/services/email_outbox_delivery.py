from collections.abc import Callable
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Any

from app.core.config import Settings, get_settings
from app.integrations.email_messages import compose_verification_email
from app.integrations.smtp_transport import EmailDeliveryError, send_email
from app.models.email_outbox import EmailOutbox
from app.security.email_outbox_encryption import (
    EmailOutboxEncryptionError,
    EmailOutboxKeyConfigurationError,
    EmailOutboxKeyUnavailableError,
    decrypt_email_payload,
)

VERIFICATION_EVENT_TYPE = "email.verification"


def _validate_verification_payload(payload: dict[str, Any]) -> tuple[str, str, str]:
    """Validate the decrypted fields required for a verification email."""
    recipient = payload.get("recipient")
    display_name = payload.get("display_name")
    raw_token = payload.get("verification_token")

    if not isinstance(recipient, str) or not recipient.strip():
        raise EmailDeliveryError("email_recipient_invalid", transient=False)

    if (
        recipient != recipient.strip()
        or any(character in recipient for character in "\r\n,;<>")
        or any(character.isspace() for character in recipient)
    ):
        raise EmailDeliveryError("email_recipient_invalid", transient=False)

    display_address, parsed_recipient = parseaddr(recipient)

    if display_address or parsed_recipient != recipient or "@" not in recipient:
        raise EmailDeliveryError("email_recipient_invalid", transient=False)

    if not isinstance(display_name, str) or not display_name.strip():
        raise EmailDeliveryError("email_display_name_invalid", transient=False)

    if not isinstance(raw_token, str) or not raw_token:
        raise EmailDeliveryError(
            "email_verification_token_invalid",
            transient=False,
        )

    return recipient, display_name, raw_token


def deliver_email_job(
    job: EmailOutbox,
    *,
    settings: Settings | None = None,
    sender: Callable[[EmailMessage], None] | None = None,
) -> None:
    """Decrypt, compose, and deliver one supported email outbox job.

    This function performs no database operations. The caller must ensure
    the job was claimed and committed before invoking external delivery.
    """
    if job.event_type != VERIFICATION_EVENT_TYPE:
        raise EmailDeliveryError("email_event_type_unsupported", transient=False)

    if job.encrypted_payload is None:
        raise EmailDeliveryError("email_payload_missing", transient=False)

    config = settings or get_settings()

    try:
        payload = decrypt_email_payload(job.event_type, job.encrypted_payload)
    except (
        EmailOutboxKeyConfigurationError,
        EmailOutboxKeyUnavailableError,
    ) as exc:
        raise EmailDeliveryError(
            "email_encryption_key_unavailable",
            transient=True,
        ) from exc
    except EmailOutboxEncryptionError as exc:
        raise EmailDeliveryError(
            "email_payload_decryption_failed",
            transient=False,
        ) from exc

    recipient, display_name, raw_token = _validate_verification_payload(payload)

    try:
        message = compose_verification_email(
            recipient_email=recipient,
            display_name=display_name,
            raw_token=raw_token,
            verification_url=config.email_verification_url,
            sender_email=config.smtp_from_email,
            sender_name=config.smtp_from_name,
        )
    except (TypeError, ValueError) as exc:
        raise EmailDeliveryError(
            "email_message_composition_failed",
            transient=False,
        ) from exc

    # Enforce the one-recipient invariant immediately before SMTP delivery.
    if len(message.get_all("To", [])) != 1 or message.get_all("Cc") or message.get_all("Bcc"):
        raise EmailDeliveryError("email_recipient_policy_violation", transient=False)

    parsed_recipients = [
        address for _, address in getaddresses(message.get_all("To", [])) if address
    ]

    if parsed_recipients != [recipient]:
        raise EmailDeliveryError("email_recipient_policy_violation", transient=False)

    if sender is not None:
        sender(message)
    else:
        send_email(message, settings=config)
