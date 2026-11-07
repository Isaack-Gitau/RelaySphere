"""create blocks

Revision ID: d8a3b5e62f19
Revises: c7f2a9d41e58
Create Date: 2026-11-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8a3b5e62f19"
down_revision: str | Sequence[str] | None = "c7f2a9d41e58"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the table that stores directional user blocks."""
    op.create_table(
        "blocks",
        sa.Column("blocker_id", sa.Uuid(), nullable=False),
        sa.Column("blocked_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "blocker_id <> blocked_id",
            name=op.f("ck_blocks_no_self_block"),
        ),
        sa.ForeignKeyConstraint(
            ["blocker_id"],
            ["users.id"],
            name=op.f("fk_blocks_blocker_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["blocked_id"],
            ["users.id"],
            name=op.f("fk_blocks_blocked_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("blocker_id", "blocked_id", name=op.f("pk_blocks")),
    )
    op.create_index("ix_blocks_blocked_id", "blocks", ["blocked_id"], unique=False)


def downgrade() -> None:
    """Drop the blocks table."""
    op.drop_index("ix_blocks_blocked_id", table_name="blocks")
    op.drop_table("blocks")
