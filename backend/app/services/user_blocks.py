import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.block import Block
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.services.user_discovery import DirectoryEntry, _eligibility_conditions

_CURSOR_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidBlockCursorError(Exception):
    """The block-list cursor is malformed or has been altered."""


@dataclass(frozen=True, slots=True)
class BlockedPage:
    items: list[DirectoryEntry]
    next_cursor: str | None


def encode_block_cursor(created_at: datetime, blocked_id: uuid.UUID) -> str:
    """Encode a pagination position as an unpadded base64url string."""
    payload = json.dumps(
        {"i": str(blocked_id), "t": created_at.astimezone(UTC).isoformat()},
        separators=(",", ":"),
        sort_keys=True,
    )
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode("ascii").rstrip("=")


def decode_block_cursor(value: str) -> tuple[datetime, uuid.UUID]:
    """Decode a cursor strictly; any deviation raises InvalidBlockCursorError."""
    if not value or not _CURSOR_PATTERN.fullmatch(value):
        raise InvalidBlockCursorError

    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        raise InvalidBlockCursorError from None

    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise InvalidBlockCursorError

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise InvalidBlockCursorError from None

    if not isinstance(data, dict) or set(data) != {"i", "t"}:
        raise InvalidBlockCursorError

    raw_id = data["i"]
    raw_time = data["t"]
    if not isinstance(raw_id, str) or not isinstance(raw_time, str):
        raise InvalidBlockCursorError

    try:
        blocked_id = uuid.UUID(raw_id)
        created_at = datetime.fromisoformat(raw_time)
    except ValueError:
        raise InvalidBlockCursorError from None

    if str(blocked_id) != raw_id:
        raise InvalidBlockCursorError
    if created_at.tzinfo is None or created_at.utcoffset() != timedelta(0):
        raise InvalidBlockCursorError
    if created_at.isoformat() != raw_time:
        raise InvalidBlockCursorError

    return created_at, blocked_id


def block_user(session: Session, blocker_id: uuid.UUID, blocked_id: uuid.UUID) -> None:
    """Record a block inside the caller's transaction; an existing block is left as is."""
    session.execute(
        insert(Block)
        .values(blocker_id=blocker_id, blocked_id=blocked_id)
        .on_conflict_do_nothing(index_elements=[Block.blocker_id, Block.blocked_id])
    )


def unblock_user(session: Session, blocker_id: uuid.UUID, blocked_id: uuid.UUID) -> None:
    """Remove the caller's block of another user, if one exists."""
    session.execute(
        delete(Block).where(Block.blocker_id == blocker_id, Block.blocked_id == blocked_id)
    )


def list_blocked_users(
    session: Session,
    blocker_id: uuid.UUID,
    limit: int,
    position: tuple[datetime, uuid.UUID] | None,
) -> BlockedPage:
    """List eligible users blocked by the caller, newest block first."""
    statement = (
        select(Block.blocked_id, Block.created_at, UsernameClaim.username, User.display_name)
        .select_from(Block)
        .join(User, User.id == Block.blocked_id)
        .join(UsernameClaim, UsernameClaim.user_id == User.id)
        .where(Block.blocker_id == blocker_id, *_eligibility_conditions())
    )

    if position is not None:
        last_created_at, last_id = position
        statement = statement.where(
            or_(
                Block.created_at < last_created_at,
                and_(Block.created_at == last_created_at, Block.blocked_id > last_id),
            )
        )

    statement = statement.order_by(Block.created_at.desc(), Block.blocked_id).limit(limit + 1)
    rows = session.execute(statement).all()

    has_more = len(rows) > limit
    page = rows[:limit]
    items = [
        DirectoryEntry(id=row.blocked_id, username=row.username, display_name=row.display_name)
        for row in page
    ]
    next_cursor = (
        encode_block_cursor(page[-1].created_at, page[-1].blocked_id) if has_more and page else None
    )

    return BlockedPage(items=items, next_cursor=next_cursor)
