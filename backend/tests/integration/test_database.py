from sqlalchemy import text
from sqlalchemy.orm import Session


def test_integration_fixture_connects_to_test_database(
    db_session: Session,
) -> None:
    database_name = db_session.scalar(text("SELECT current_database()"))
    users_table = db_session.scalar(text("SELECT to_regclass('public.users')"))

    assert database_name == "relaysphere_test"
    assert users_table == "users"
