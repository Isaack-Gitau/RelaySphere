"""create email change requests

Revision ID: a5d3c8e27f10
Revises: 7c2e5a91d4b3
Create Date: 2026-11-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a5d3c8e27f10"
down_revision: str | Sequence[str] | None = "7c2e5a91d4b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the table that stores hashed email change requests."""
    op.create_table(
        "email_change_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("new_email", sa.String(length=320), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_email_change_requests_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_change_requests")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_email_change_requests_token_hash")),
    )
    op.create_index(
        op.f("ix_email_change_requests_user_id"),
        "email_change_requests",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "uq_email_change_requests_user_id_active",
        "email_change_requests",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("used_at IS NULL AND superseded_at IS NULL"),
    )


def downgrade() -> None:
    """Drop the email change request table."""
    op.drop_index("uq_email_change_requests_user_id_active", table_name="email_change_requests")
    op.drop_index(op.f("ix_email_change_requests_user_id"), table_name="email_change_requests")
    op.drop_table("email_change_requests")
