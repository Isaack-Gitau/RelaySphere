"""create refresh sessions and consumed-token history

Revision ID: f4a9b27c61de
Revises: d173c0bcc1bb
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f4a9b27c61de"
down_revision: str | Sequence[str] | None = "d173c0bcc1bb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create refresh-session storage."""
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_sessions_token_hash")),
    )
    op.create_index(
        op.f("ix_refresh_sessions_user_id"),
        "refresh_sessions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_refresh_sessions_expires_at"),
        "refresh_sessions",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "refresh_token_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["refresh_sessions.id"],
            name=op.f("fk_refresh_token_history_session_id_refresh_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_token_history")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_token_history_token_hash")),
    )
    op.create_index(
        op.f("ix_refresh_token_history_session_id"),
        "refresh_token_history",
        ["session_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove refresh-session storage."""
    op.drop_index(
        op.f("ix_refresh_token_history_session_id"),
        table_name="refresh_token_history",
    )
    op.drop_table("refresh_token_history")
    op.drop_index(
        op.f("ix_refresh_sessions_expires_at"),
        table_name="refresh_sessions",
    )
    op.drop_index(
        op.f("ix_refresh_sessions_user_id"),
        table_name="refresh_sessions",
    )
    op.drop_table("refresh_sessions")
