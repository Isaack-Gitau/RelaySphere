"""create authoritative username claims registry

Revision ID: b6e4c91a2d73
Revises: a5d3c8e27f10
Create Date: 2026-11-05
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b6e4c91a2d73"
down_revision: str | Sequence[str] | None = "a5d3c8e27f10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


RESERVED_USERNAMES = (
    "admin",
    "administrator",
    "api",
    "help",
    "moderator",
    "official",
    "relay",
    "relaysphere",
    "root",
    "security",
    "support",
    "system",
)


def upgrade() -> None:
    """Create the username registry without silently migrating existing users."""
    bind = op.get_bind()

    existing_users = bind.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM users LIMIT 1)")
    ).scalar_one()

    if existing_users:
        raise RuntimeError(
            "Username claims migration stopped: users already exist. "
            "Define an explicit username onboarding/data migration first."
        )

    op.create_table(
        "username_claims",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=30), nullable=False),
        sa.Column("claim_type", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("registration_attempt_id", sa.Uuid(), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_username_claims_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_username_claims")),
        sa.UniqueConstraint(
            "username",
            name=op.f("uq_username_claims_username"),
        ),
        sa.CheckConstraint(
            "username ~ '^[a-z][a-z0-9_]{1,28}[a-z0-9]$' "
            "AND username !~ '__'",
            name=op.f("ck_username_claims_username_format"),
        ),
        sa.CheckConstraint(
            "claim_type IN ('reserved', 'reservation', 'permanent')",
            name=op.f("ck_username_claims_claim_type_valid"),
        ),
        sa.CheckConstraint(
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
            name=op.f("ck_username_claims_claim_state_valid"),
        ),
    )

    op.create_index(
        "uq_username_claims_permanent_user",
        "username_claims",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("claim_type = 'permanent'"),
    )
    op.create_index(
        "uq_username_claims_reservation_attempt",
        "username_claims",
        ["registration_attempt_id"],
        unique=True,
        postgresql_where=sa.text("claim_type = 'reservation'"),
    )

    reserved_table = sa.table(
        "username_claims",
        sa.column("id", sa.Uuid()),
        sa.column("username", sa.String(length=30)),
        sa.column("claim_type", sa.String(length=16)),
    )
    op.bulk_insert(
        reserved_table,
        [
            {
                "id": uuid.uuid4(),
                "username": username,
                "claim_type": "reserved",
            }
            for username in RESERVED_USERNAMES
        ],
    )


def downgrade() -> None:
    """Refuse to remove username claims belonging to users or attempts."""
    bind = op.get_bind()

    has_user_claims = bind.execute(
        sa.text(
            "SELECT EXISTS ("
            "SELECT 1 FROM username_claims "
            "WHERE claim_type IN ('reservation', 'permanent')"
            ")"
        )
    ).scalar_one()

    if has_user_claims:
        raise RuntimeError(
            "Username claims downgrade stopped: temporary or permanent "
            "claims exist. Resolve them explicitly before removing the registry."
        )

    op.drop_index(
        "uq_username_claims_reservation_attempt",
        table_name="username_claims",
    )
    op.drop_index(
        "uq_username_claims_permanent_user",
        table_name="username_claims",
    )
    op.drop_table("username_claims")
