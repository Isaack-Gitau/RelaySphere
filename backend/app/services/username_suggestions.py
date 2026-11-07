import re
import unicodedata

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.username_claim import UsernameClaim

MAX_USERNAME_LENGTH = 30
MAX_SUGGESTIONS = 5
MAX_CANDIDATES = 64


def _is_valid_candidate(username: str) -> bool:
    """Check the username format enforced by the database."""
    return (
        3 <= len(username) <= MAX_USERNAME_LENGTH
        and re.fullmatch(r"[a-z][a-z0-9_]*[a-z0-9]", username) is not None
        and "__" not in username
    )


def generate_username_candidates(display_name: str) -> list[str]:
    """Generate deterministic, valid username candidates from a display name."""
    ascii_name = (
        unicodedata.normalize("NFKD", display_name)
        .encode("ascii", "ignore")
        .decode("ascii")
        .lower()
    )

    base = re.sub(r"[^a-z0-9]+", "_", ascii_name).strip("_")

    if not base:
        return []

    if base[0].isdigit():
        base = f"user_{base}"

    base = base[:MAX_USERNAME_LENGTH].rstrip("_")

    # Very short names are better handled through manual username entry.
    if len(base) < 2:
        return []

    candidates: list[str] = []

    def add_candidate(candidate: str) -> None:
        if (
            candidate not in candidates
            and len(candidates) < MAX_CANDIDATES
            and _is_valid_candidate(candidate)
        ):
            candidates.append(candidate)

    add_candidate(base)
    add_candidate(base.replace("_", ""))

    # Keep the suffix while truncating the base to the database limit.
    for number in range(2, 1000):
        suffix = str(number)
        prefix = base[: MAX_USERNAME_LENGTH - len(suffix)].rstrip("_")
        add_candidate(f"{prefix}{suffix}")

        if len(candidates) >= MAX_CANDIDATES:
            break

    return candidates


def suggest_usernames(session: Session, display_name: str) -> list[str]:
    """Return up to five currently available username candidates."""
    candidates = generate_username_candidates(display_name)

    if not candidates:
        return []

    statement = select(UsernameClaim.username).where(
        UsernameClaim.username.in_(candidates),
        or_(
            UsernameClaim.claim_type != "reservation",
            UsernameClaim.expires_at > func.now(),
        ),
    )

    unavailable = set(session.scalars(statement).all())

    return [candidate for candidate in candidates if candidate not in unavailable][:MAX_SUGGESTIONS]
