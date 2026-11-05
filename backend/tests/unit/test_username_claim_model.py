import uuid

from sqlalchemy import CheckConstraint, Index, UniqueConstraint

from app.db.base import Base
from app.models import User, UsernameClaim


def test_username_claim_maps_to_registered_table() -> None:
    assert UsernameClaim.__tablename__ == "username_claims"
    assert UsernameClaim.__table__ is Base.metadata.tables["username_claims"]


def test_username_claim_has_expected_columns() -> None:
    columns = UsernameClaim.__table__.c

    assert set(columns.keys()) == {
        "id",
        "username",
        "claim_type",
        "user_id",
        "registration_attempt_id",
        "token_hash",
        "expires_at",
        "created_at",
    }
    assert columns.id.primary_key is True
    assert columns.username.nullable is False
    assert columns.claim_type.nullable is False
    assert columns.user_id.nullable is True
    assert columns.registration_attempt_id.nullable is True
    assert columns.token_hash.nullable is True
    assert columns.expires_at.nullable is True


def test_username_claim_has_database_constraints() -> None:
    table = UsernameClaim.__table__

    unique_constraints = {
        tuple(constraint.columns.keys())
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("username",) in unique_constraints

    check_names = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert check_names == {
        "ck_username_claims_username_format",
        "ck_username_claims_claim_type_valid",
        "ck_username_claims_claim_state_valid",
    }


def test_username_claim_has_partial_unique_indexes() -> None:
    indexes = {
        index.name: index
        for index in UsernameClaim.__table__.indexes
        if isinstance(index, Index)
    }

    assert indexes["uq_username_claims_permanent_user"].unique is True
    assert list(indexes["uq_username_claims_permanent_user"].columns.keys()) == [
        "user_id"
    ]

    assert indexes["uq_username_claims_reservation_attempt"].unique is True
    assert list(
        indexes["uq_username_claims_reservation_attempt"].columns.keys()
    ) == ["registration_attempt_id"]


def test_user_exposes_username_through_permanent_claim_relationship() -> None:
    assert "username_claim" in User.__mapper__.relationships
    assert "username" not in User.__table__.c

    user = User(
        email="username-test@example.com",
        display_name="Username Test",
        password_hash=None,
    )
    claim = UsernameClaim(
        id=uuid.uuid4(),
        username="username_test",
        claim_type="permanent",
        user_id=user.id,
    )

    user.username_claim = claim

    assert user.username == "username_test"
