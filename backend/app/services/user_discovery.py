import base64
import binascii
import json
import re
import unicodedata
import uuid
from dataclasses import dataclass

from sqlalchemy import and_, case, collate, exists, func, literal_column, or_, select
from sqlalchemy.orm import Session

from app.models.block import Block
from app.models.user import User
from app.models.username_claim import UsernameClaim

MIN_QUERY_LENGTH = 2
MAX_QUERY_LENGTH = 80
LIKE_ESCAPE = "!"

_CURSOR_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,28}[a-z0-9]$")


class InvalidQueryError(Exception):
    """The search query is too short, too long, or contains control characters."""


class InvalidCursorError(Exception):
    """The pagination cursor is malformed or has been altered."""


@dataclass(frozen=True, slots=True)
class DirectoryEntry:
    id: uuid.UUID
    username: str
    display_name: str


@dataclass(frozen=True, slots=True)
class SearchPage:
    items: list[DirectoryEntry]
    next_cursor: str | None


def normalize_query(raw: str) -> str:
    """Trim and lowercase a search query, rejecting unusable input."""
    value = raw.strip().lower()

    if any(unicodedata.category(char) == "Cc" for char in value):
        raise InvalidQueryError
    if not MIN_QUERY_LENGTH <= len(value) <= MAX_QUERY_LENGTH:
        raise InvalidQueryError

    return value


def escape_like(value: str) -> str:
    """Escape LIKE wildcards so user input always matches literally."""
    return (
        value.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", LIKE_ESCAPE + "%")
        .replace("_", LIKE_ESCAPE + "_")
    )


def encode_cursor(rank: int, username: str) -> str:
    """Encode a pagination position as an unpadded base64url string."""
    payload = json.dumps({"r": rank, "u": username}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode("ascii").rstrip("=")


def decode_cursor(value: str) -> tuple[int, str]:
    """Decode a cursor strictly; any deviation raises InvalidCursorError."""
    if not value or not _CURSOR_PATTERN.fullmatch(value):
        raise InvalidCursorError

    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        raise InvalidCursorError from None

    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise InvalidCursorError

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise InvalidCursorError from None

    if not isinstance(data, dict) or set(data) != {"r", "u"}:
        raise InvalidCursorError

    rank = data["r"]
    username = data["u"]

    if type(rank) is not int or rank not in (0, 1):
        raise InvalidCursorError
    if (
        not isinstance(username, str)
        or not _USERNAME_PATTERN.fullmatch(username)
        or "__" in username
    ):
        raise InvalidCursorError

    return rank, username


def _eligibility_conditions() -> tuple:
    return (
        User.is_active.is_(True),
        User.email_verified_at.is_not(None),
        UsernameClaim.claim_type == "permanent",
    )


def _not_blocked_either_way(viewer_id: uuid.UUID):
    """Exclude users who blocked the viewer and users the viewer blocked."""
    return ~exists().where(
        or_(
            and_(Block.blocker_id == viewer_id, Block.blocked_id == User.id),
            and_(Block.blocker_id == User.id, Block.blocked_id == viewer_id),
        )
    )


def search_users(
    session: Session,
    caller_id: uuid.UUID,
    query: str,
    limit: int,
    position: tuple[int, str] | None,
) -> SearchPage:
    """Prefix-search eligible users by username (rank 0) or display name (rank 1)."""
    pattern = escape_like(query) + "%"
    username_match = UsernameClaim.username.like(pattern, escape=LIKE_ESCAPE)
    display_match = func.lower(User.display_name).like(pattern, escape=LIKE_ESCAPE)
    rank = case((username_match, literal_column("0")), else_=literal_column("1"))
    username_c = collate(UsernameClaim.username, "C")

    statement = (
        select(User.id, UsernameClaim.username, User.display_name, rank.label("rank"))
        .select_from(User)
        .join(UsernameClaim, UsernameClaim.user_id == User.id)
        .where(
            *_eligibility_conditions(),
            User.id != caller_id,
            _not_blocked_either_way(caller_id),
            or_(username_match, display_match),
        )
    )

    if position is not None:
        last_rank, last_username = position
        statement = statement.where(
            or_(rank > last_rank, and_(rank == last_rank, username_c > last_username))
        )

    statement = statement.order_by(rank, username_c).limit(limit + 1)
    rows = session.execute(statement).all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [
        DirectoryEntry(id=row.id, username=row.username, display_name=row.display_name)
        for row in page
    ]
    next_cursor = encode_cursor(page[-1].rank, page[-1].username) if has_more and page else None

    return SearchPage(items=items, next_cursor=next_cursor)


def get_eligible_user(
    session: Session,
    user_id: uuid.UUID,
    viewer_id: uuid.UUID | None = None,
) -> DirectoryEntry | None:
    """Return the public entry for an eligible user, or None for anyone else."""
    statement = (
        select(User.id, UsernameClaim.username, User.display_name)
        .select_from(User)
        .join(UsernameClaim, UsernameClaim.user_id == User.id)
        .where(*_eligibility_conditions(), User.id == user_id)
    )
    if viewer_id is not None:
        statement = statement.where(_not_blocked_either_way(viewer_id))

    row = session.execute(statement).first()

    if row is None:
        return None

    return DirectoryEntry(id=row.id, username=row.username, display_name=row.display_name)
