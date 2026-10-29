from app.core.config import get_settings


def send_verification_email(
    recipient_email: str,
    raw_token: str,
) -> None:
    """Display a verification message in the terminal during local development."""
    settings = get_settings()

    if settings.environment.lower() not in {"development", "testing"}:
        raise RuntimeError("Console email delivery is only available in development or testing.")

    print(
        "\n"
        "========== RELAYSPHERE DEVELOPMENT EMAIL ==========\n"
        "This message was NOT sent to a real email inbox.\n"
        f"To: {recipient_email}\n"
        "Subject: Verify your RelaySphere email address\n"
        f"Verification token: {raw_token}\n"
        "\n"
        "To verify the account, POST to /api/v1/auth/verify-email\n"
        "with this JSON body:\n"
        '{"token": "<paste the verification token here>"}\n'
        "===================================================\n",
        flush=True,
    )
