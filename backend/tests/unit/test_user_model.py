import uuid

from sqlalchemy import Boolean, DateTime, String, Table, Uuid

from app.db.base import Base
from app.models import User


def test_user_maps_to_users_table() -> None:
    assert User.__tablename__ == "users"
    assert User.__table__ is Base.metadata.tables["users"]


def test_user_primary_key_is_uuid() -> None:
    column = User.__table__.c.id

    assert column.primary_key is True
    assert isinstance(column.type, Uuid)
    assert column.type.as_uuid is True
    assert column.nullable is False


def test_user_column_types_and_nullability() -> None:
    columns = User.__table__.c

    assert isinstance(columns.email.type, String)
    assert columns.email.type.length == 320
    assert columns.email.nullable is False

    assert isinstance(columns.password_hash.type, String)
    assert columns.password_hash.type.length == 255
    assert columns.password_hash.nullable is True

    assert isinstance(columns.display_name.type, String)
    assert columns.display_name.type.length == 80
    assert columns.display_name.nullable is False

    assert isinstance(columns.is_active.type, Boolean)
    assert columns.is_active.nullable is False

    assert isinstance(columns.email_verified_at.type, DateTime)
    assert columns.email_verified_at.nullable is True

    assert isinstance(columns.created_at.type, DateTime)
    assert columns.created_at.nullable is False

    assert isinstance(columns.updated_at.type, DateTime)
    assert columns.updated_at.nullable is False


def test_user_default_configuration() -> None:
    columns = User.__table__.c

    assert columns.id.default is not None
    assert callable(columns.id.default.arg)

    assert columns.is_active.default is not None
    assert columns.is_active.default.arg is True
    assert str(columns.is_active.server_default.arg) == "true"

    assert columns.created_at.server_default is not None
    assert columns.updated_at.server_default is not None
    assert columns.updated_at.onupdate is not None


def test_user_email_has_unique_index() -> None:
    table = User.__table__
    assert isinstance(table, Table)

    email_indexes = [index for index in table.indexes if list(index.columns.keys()) == ["email"]]

    assert len(email_indexes) == 1
    assert email_indexes[0].unique is True


def test_user_uuid_default_generates_unique_ids() -> None:
    uuid_default = User.__table__.c.id.default

    assert uuid_default is not None

    first_id = uuid_default.arg(None)
    second_id = uuid_default.arg(None)

    assert isinstance(first_id, uuid.UUID)
    assert isinstance(second_id, uuid.UUID)
    assert first_id != second_id
