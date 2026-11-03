"""allow email outbox payload cleanup

Revision ID: 0bd78bf5f36a
Revises: 5846f7f35424
Create Date: 2026-11-03 20:02:37.461950
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0bd78bf5f36a"
down_revision: str | Sequence[str] | None = "5846f7f35424"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "email_outbox",
        "encrypted_payload",
        existing_type=sa.LargeBinary(),
        nullable=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    has_null_payloads = bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM email_outbox WHERE encrypted_payload IS NULL)")
    ).scalar_one()

    if has_null_payloads:
        raise RuntimeError(
            "Cannot restore encrypted_payload to NOT NULL: some payloads have already been cleared."
        )

    op.alter_column(
        "email_outbox",
        "encrypted_payload",
        existing_type=sa.LargeBinary(),
        nullable=False,
    )
