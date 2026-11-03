"""add reauthenticated_at to refresh sessions

Revision ID: 3b8f6d1e9a40
Revises: 0bd78bf5f36a
Create Date: 2026-11-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3b8f6d1e9a40"
down_revision: str | Sequence[str] | None = "0bd78bf5f36a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the recent-reauthentication marker; NULL means reauthentication is required."""
    op.add_column(
        "refresh_sessions",
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Remove the recent-reauthentication marker."""
    op.drop_column("refresh_sessions", "reauthenticated_at")
