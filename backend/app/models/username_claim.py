import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UsernameClaim(Base):
    """Authoritative registry for reserved, temporary, and permanent usernames."""

    __tablename__ = "username_claims"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(String(30), nullable=False)
    claim_type: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    registration_attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("username", name="uq_username_claims_username"),
        CheckConstraint(
            "username ~ '^[a-z][a-z0-9_]{1,28}[a-z0-9]$' AND username !~ '__'",
            name="username_format",
        ),
        CheckConstraint(
            "claim_type IN ('reserved', 'reservation', 'permanent')",
            name="claim_type_valid",
        ),
        CheckConstraint(
            "("
            "claim_type = 'reserved' "
            "AND user_id IS NULL "
            "AND registration_attempt_id IS NULL "
            "AND token_hash IS NULL "
            "AND expires_at IS NULL"
            ") OR ("
            "claim_type = 'reservation' "
            "AND user_id IS NULL "
            "AND registration_attempt_id IS NOT NULL "
            "AND token_hash IS NOT NULL "
            "AND expires_at IS NOT NULL"
            ") OR ("
            "claim_type = 'permanent' "
            "AND user_id IS NOT NULL "
            "AND registration_attempt_id IS NULL "
            "AND token_hash IS NULL "
            "AND expires_at IS NULL"
            ")",
            name="claim_state_valid",
        ),
        Index(
            "uq_username_claims_permanent_user",
            "user_id",
            unique=True,
            postgresql_where=text("claim_type = 'permanent'"),
        ),
        Index(
            "uq_username_claims_reservation_attempt",
            "registration_attempt_id",
            unique=True,
            postgresql_where=text("claim_type = 'reservation'"),
        ),
    )
