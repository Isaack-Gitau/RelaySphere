from email.message import EmailMessage
from email.utils import formataddr
from html import escape
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.password_reset import PASSWORD_RESET_TOKEN_EXPIRY_MINUTES

VERIFICATION_EMAIL_SUBJECT = "Verify your RelaySphere email address"
PASSWORD_RESET_EMAIL_SUBJECT = "Reset your RelaySphere password"


def _build_token_url(base_url: str, raw_token: str, purpose: str) -> str:
    """Build a URL containing the URL-encoded token; purpose names the flow in errors."""
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError(f"A {purpose} token is required.")

    try:
        parsed = urlsplit(base_url)
    except ValueError as exc:
        raise ValueError(f"The {purpose} URL is invalid.") from exc

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"The {purpose} URL must be an absolute HTTP or HTTPS URL.")

    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key != "token"
    ]
    query.append(("token", raw_token))

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            "",
        )
    )


def build_verification_url(base_url: str, raw_token: str) -> str:
    """Build a verification URL containing the URL-encoded token."""
    return _build_token_url(base_url, raw_token, "verification")


def build_password_reset_url(base_url: str, raw_token: str) -> str:
    """Build a password reset URL containing the URL-encoded token."""
    return _build_token_url(base_url, raw_token, "password reset")


def compose_verification_email(
    *,
    recipient_email: str,
    display_name: str,
    raw_token: str,
    verification_url: str,
    sender_email: str,
    sender_name: str = "RelaySphere",
) -> EmailMessage:
    """Compose a verification email with plain-text and HTML alternatives."""
    if not recipient_email.strip():
        raise ValueError("A recipient email address is required.")

    if not sender_email.strip():
        raise ValueError("A sender email address is required.")

    if not display_name.strip():
        raise ValueError("A display name is required.")

    link = build_verification_url(verification_url, raw_token)

    safe_name = escape(display_name)
    safe_link = escape(link, quote=True)

    message = EmailMessage()
    message["Subject"] = VERIFICATION_EMAIL_SUBJECT
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient_email

    message.set_content(
        f"""Hello {display_name},

Welcome to RelaySphere.

Please verify your email address by opening this link:

{link}

This link expires in 24 hours. If you did not create a RelaySphere account,
you can ignore this email.

RelaySphere
"""
    )

    message.add_alternative(
        f"""<!doctype html>
<html lang="en">
  <body>
    <p>Hello {safe_name},</p>
    <p>Welcome to RelaySphere.</p>
    <p>Please verify your email address by clicking the link below:</p>
    <p><a href="{safe_link}">Verify your email address</a></p>
    <p>This link expires in 24 hours. If you did not create a RelaySphere
    account, you can ignore this email.</p>
    <p>RelaySphere</p>
  </body>
</html>
""",
        subtype="html",
    )

    return message


def compose_password_reset_email(
    *,
    recipient_email: str,
    display_name: str,
    raw_token: str,
    reset_url: str,
    sender_email: str,
    sender_name: str = "RelaySphere",
) -> EmailMessage:
    """Compose a password reset email with plain-text and HTML alternatives."""
    if not recipient_email.strip():
        raise ValueError("A recipient email address is required.")

    if not sender_email.strip():
        raise ValueError("A sender email address is required.")

    if not display_name.strip():
        raise ValueError("A display name is required.")

    link = build_password_reset_url(reset_url, raw_token)
    minutes = PASSWORD_RESET_TOKEN_EXPIRY_MINUTES

    safe_name = escape(display_name)
    safe_link = escape(link, quote=True)

    message = EmailMessage()
    message["Subject"] = PASSWORD_RESET_EMAIL_SUBJECT
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient_email

    message.set_content(
        f"""Hello {display_name},

We received a request to reset the password for your RelaySphere account.

To choose a new password, open this link:

{link}

This link expires in {minutes} minutes and can be used only once.

If you did not request a password reset, you can ignore this email.
Your password will not change unless you use the link above.

RelaySphere
"""
    )

    message.add_alternative(
        f"""<!doctype html>
<html lang="en">
  <body>
    <p>Hello {safe_name},</p>
    <p>We received a request to reset the password for your RelaySphere account.</p>
    <p>To choose a new password, click the link below:</p>
    <p><a href="{safe_link}">Reset your password</a></p>
    <p>This link expires in {minutes} minutes and can be used only once.</p>
    <p>If you did not request a password reset, you can ignore this email.
    Your password will not change unless you use the link above.</p>
    <p>RelaySphere</p>
  </body>
</html>
""",
        subtype="html",
    )

    return message
