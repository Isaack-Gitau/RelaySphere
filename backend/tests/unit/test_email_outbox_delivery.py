from email.message import EmailMessage
from types import SimpleNamespace

import pytest

from app.core.password_reset import PASSWORD_RESET_EMAIL_EVENT
from app.integrations.smtp_transport import EmailDeliveryError
from app.services import email_outbox_delivery as delivery


def make_job(
    *,
    event_type: str = "email.verification",
    encrypted_payload: bytes | None = b"encrypted-payload",
):
    return SimpleNamespace(
        event_type=event_type,
        encrypted_payload=encrypted_payload,
    )


def make_settings():
    return SimpleNamespace(
        email_verification_url="https://app.example.test/verify-email",
        smtp_from_email="noreply@example.test",
        smtp_from_name="RelaySphere",
    )


def make_message(recipient: str = "person@example.test") -> EmailMessage:
    message = EmailMessage()
    message["From"] = "noreply@example.test"
    message["To"] = recipient
    message["Subject"] = "Verify your RelaySphere email address"
    message.set_content("Verification message")
    return message


@pytest.fixture
def decrypted_payload(monkeypatch):
    payload = {
        "recipient": "person@example.test",
        "display_name": "RelaySphere User",
        "verification_token": "test-verification-token",
    }

    monkeypatch.setattr(
        delivery,
        "decrypt_email_payload",
        lambda event_type, encrypted_payload: payload,
    )

    return payload


def test_deliver_email_job_composes_and_sends_verification_email(
    monkeypatch,
    decrypted_payload,
):
    sent_messages = []
    compose_calls = []

    def compose(**kwargs):
        compose_calls.append(kwargs)
        return make_message(kwargs["recipient_email"])

    monkeypatch.setattr(delivery, "compose_verification_email", compose)

    delivery.deliver_email_job(
        make_job(),
        settings=make_settings(),
        sender=sent_messages.append,
    )

    assert len(sent_messages) == 1
    assert sent_messages[0]["To"] == "person@example.test"
    assert compose_calls == [
        {
            "recipient_email": "person@example.test",
            "display_name": "RelaySphere User",
            "raw_token": "test-verification-token",
            "verification_url": "https://app.example.test/verify-email",
            "sender_email": "noreply@example.test",
            "sender_name": "RelaySphere",
        }
    ]


def test_deliver_email_job_uses_smtp_transport_when_sender_not_injected(
    monkeypatch,
    decrypted_payload,
):
    sent = []
    config = make_settings()

    monkeypatch.setattr(
        delivery,
        "compose_verification_email",
        lambda **kwargs: make_message(kwargs["recipient_email"]),
    )
    monkeypatch.setattr(
        delivery,
        "send_email",
        lambda message, settings: sent.append((message, settings)),
    )

    delivery.deliver_email_job(make_job(), settings=config)

    assert len(sent) == 1
    assert sent[0][0]["To"] == "person@example.test"
    assert sent[0][1] is config


def test_deliver_email_job_rejects_unsupported_event_without_decrypting(
    monkeypatch,
):
    def unexpected_decrypt(*args):
        pytest.fail("Unsupported event must not be decrypted.")

    monkeypatch.setattr(delivery, "decrypt_email_payload", unexpected_decrypt)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(event_type="email.unknown"),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_event_type_unsupported"
    assert error.value.transient is False


def test_deliver_email_job_rejects_missing_encrypted_payload():
    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(encrypted_payload=None),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_payload_missing"
    assert error.value.transient is False


@pytest.mark.parametrize(
    ("exception", "expected_code", "expected_transient"),
    [
        (
            delivery.EmailOutboxKeyConfigurationError("Internal keyring detail"),
            "email_encryption_key_unavailable",
            True,
        ),
        (
            delivery.EmailOutboxKeyUnavailableError("Internal missing-key detail"),
            "email_encryption_key_unavailable",
            True,
        ),
        (
            delivery.EmailOutboxEncryptionError("Internal ciphertext detail"),
            "email_payload_decryption_failed",
            False,
        ),
    ],
)
def test_deliver_email_job_classifies_decryption_failures(
    monkeypatch,
    exception,
    expected_code,
    expected_transient,
):
    def fail_decryption(*args):
        raise exception

    monkeypatch.setattr(delivery, "decrypt_email_payload", fail_decryption)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == expected_code
    assert error.value.transient is expected_transient
    assert "Internal" not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("recipient", "", "email_recipient_invalid"),
        ("recipient", " person@example.test", "email_recipient_invalid"),
        ("recipient", "person@example.test,other@example.test", "email_recipient_invalid"),
        ("recipient", "Person <person@example.test>", "email_recipient_invalid"),
        ("recipient", "person example.test", "email_recipient_invalid"),
        ("display_name", "", "email_display_name_invalid"),
        ("display_name", None, "email_display_name_invalid"),
        ("verification_token", "", "email_verification_token_invalid"),
        ("verification_token", None, "email_verification_token_invalid"),
    ],
)
def test_deliver_email_job_rejects_invalid_payload_fields(
    monkeypatch,
    field,
    value,
    expected_code,
):
    payload = {
        "recipient": "person@example.test",
        "display_name": "RelaySphere User",
        "verification_token": "test-verification-token",
    }
    payload[field] = value

    monkeypatch.setattr(
        delivery,
        "decrypt_email_payload",
        lambda *args: payload,
    )

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == expected_code
    assert error.value.transient is False


def test_deliver_email_job_rejects_multiple_recipients_in_composed_message(
    monkeypatch,
    decrypted_payload,
):
    monkeypatch.setattr(
        delivery,
        "compose_verification_email",
        lambda **kwargs: make_message("person@example.test, other@example.test"),
    )

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_recipient_policy_violation"
    assert error.value.transient is False


@pytest.mark.parametrize("header", ["Cc", "Bcc"])
def test_deliver_email_job_rejects_copy_recipient_headers(
    monkeypatch,
    decrypted_payload,
    header,
):
    def compose(**kwargs):
        message = make_message(kwargs["recipient_email"])
        message[header] = "other@example.test"
        return message

    monkeypatch.setattr(delivery, "compose_verification_email", compose)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_recipient_policy_violation"
    assert error.value.transient is False


def test_deliver_email_job_translates_composition_failure(
    monkeypatch,
    decrypted_payload,
):
    def fail_composition(**kwargs):
        raise ValueError("Sensitive composition detail")

    monkeypatch.setattr(
        delivery,
        "compose_verification_email",
        fail_composition,
    )

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_message_composition_failed"
    assert error.value.transient is False
    assert "Sensitive composition detail" not in str(error.value)


def make_reset_settings():
    return SimpleNamespace(
        email_password_reset_url="https://app.example.test/reset-password",
        smtp_from_email="noreply@example.test",
        smtp_from_name="RelaySphere",
    )


def make_reset_message(recipient: str = "person@example.test") -> EmailMessage:
    message = EmailMessage()
    message["From"] = "noreply@example.test"
    message["To"] = recipient
    message["Subject"] = "Reset your RelaySphere password"
    message.set_content("Password reset message")
    return message


def make_reset_payload():
    return {
        "recipient": "person@example.test",
        "display_name": "RelaySphere User",
        "password_reset_token": "test-reset-token",
    }


@pytest.fixture
def decrypted_reset_payload(monkeypatch):
    payload = make_reset_payload()

    monkeypatch.setattr(
        delivery,
        "decrypt_email_payload",
        lambda event_type, encrypted_payload: payload,
    )

    return payload


def test_event_type_constants_match_the_enqueuing_services():
    assert delivery.PASSWORD_RESET_EVENT_TYPE == PASSWORD_RESET_EMAIL_EVENT
    assert delivery.VERIFICATION_EVENT_TYPE == "email.verification"


def test_deliver_email_job_composes_and_sends_password_reset_email(
    monkeypatch,
    decrypted_reset_payload,
):
    sent_messages = []
    compose_calls = []

    def compose(**kwargs):
        compose_calls.append(kwargs)
        return make_reset_message(kwargs["recipient_email"])

    monkeypatch.setattr(delivery, "compose_password_reset_email", compose)
    monkeypatch.setattr(
        delivery,
        "compose_verification_email",
        lambda **kwargs: pytest.fail("Verification composer must not be used."),
    )

    delivery.deliver_email_job(
        make_job(event_type="email.password_reset"),
        settings=make_reset_settings(),
        sender=sent_messages.append,
    )

    assert len(sent_messages) == 1
    assert sent_messages[0]["To"] == "person@example.test"
    assert compose_calls == [
        {
            "recipient_email": "person@example.test",
            "display_name": "RelaySphere User",
            "raw_token": "test-reset-token",
            "reset_url": "https://app.example.test/reset-password",
            "sender_email": "noreply@example.test",
            "sender_name": "RelaySphere",
        }
    ]


def test_deliver_email_job_sends_password_reset_through_smtp_transport(
    monkeypatch,
    decrypted_reset_payload,
):
    sent = []
    config = make_reset_settings()

    monkeypatch.setattr(
        delivery,
        "compose_password_reset_email",
        lambda **kwargs: make_reset_message(kwargs["recipient_email"]),
    )
    monkeypatch.setattr(
        delivery,
        "send_email",
        lambda message, settings: sent.append((message, settings)),
    )

    delivery.deliver_email_job(make_job(event_type="email.password_reset"), settings=config)

    assert len(sent) == 1
    assert sent[0][0]["To"] == "person@example.test"
    assert sent[0][1] is config


def test_deliver_email_job_builds_real_password_reset_message(
    decrypted_reset_payload,
):
    sent_messages = []

    delivery.deliver_email_job(
        make_job(event_type="email.password_reset"),
        settings=make_reset_settings(),
        sender=sent_messages.append,
    )

    assert len(sent_messages) == 1
    message = sent_messages[0]
    assert message["Subject"] == "Reset your RelaySphere password"
    assert message["To"] == "person@example.test"

    plain_part = message.get_body(preferencelist=("plain",))
    assert plain_part is not None
    assert "https://app.example.test/reset-password?token=test-reset-token" in (
        plain_part.get_content()
    )


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("recipient", "", "email_recipient_invalid"),
        ("recipient", "person@example.test,other@example.test", "email_recipient_invalid"),
        ("display_name", "", "email_display_name_invalid"),
        ("display_name", None, "email_display_name_invalid"),
        ("password_reset_token", "", "email_password_reset_token_invalid"),
        ("password_reset_token", None, "email_password_reset_token_invalid"),
    ],
)
def test_deliver_email_job_rejects_invalid_password_reset_payload_fields(
    monkeypatch,
    field,
    value,
    expected_code,
):
    payload = make_reset_payload()
    payload[field] = value

    monkeypatch.setattr(delivery, "decrypt_email_payload", lambda *args: payload)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(event_type="email.password_reset"),
            settings=make_reset_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == expected_code
    assert error.value.transient is False


def test_password_reset_job_rejects_payload_with_only_a_verification_token(monkeypatch):
    payload = {
        "recipient": "person@example.test",
        "display_name": "RelaySphere User",
        "verification_token": "test-verification-token",
    }
    monkeypatch.setattr(delivery, "decrypt_email_payload", lambda *args: payload)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(event_type="email.password_reset"),
            settings=make_reset_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_password_reset_token_invalid"
    assert error.value.transient is False


def test_verification_job_rejects_payload_with_only_a_password_reset_token(monkeypatch):
    payload = make_reset_payload()
    monkeypatch.setattr(delivery, "decrypt_email_payload", lambda *args: payload)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(),
            settings=make_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_verification_token_invalid"
    assert error.value.transient is False


def test_deliver_email_job_rejects_multiple_recipients_in_password_reset_message(
    monkeypatch,
    decrypted_reset_payload,
):
    monkeypatch.setattr(
        delivery,
        "compose_password_reset_email",
        lambda **kwargs: make_reset_message("person@example.test, other@example.test"),
    )

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(event_type="email.password_reset"),
            settings=make_reset_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_recipient_policy_violation"
    assert error.value.transient is False


def test_deliver_email_job_translates_password_reset_composition_failure(
    monkeypatch,
    decrypted_reset_payload,
):
    def fail_composition(**kwargs):
        raise ValueError("Sensitive composition detail")

    monkeypatch.setattr(delivery, "compose_password_reset_email", fail_composition)

    with pytest.raises(EmailDeliveryError) as error:
        delivery.deliver_email_job(
            make_job(event_type="email.password_reset"),
            settings=make_reset_settings(),
            sender=lambda message: pytest.fail("Email must not be sent."),
        )

    assert error.value.code == "email_message_composition_failed"
    assert error.value.transient is False
    assert "Sensitive composition detail" not in str(error.value)
