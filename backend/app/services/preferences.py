import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.user_preferences import UserPreferences

DEFAULT_THEME = "system"
DEFAULT_SHOW_PRESENCE = True


@dataclass(frozen=True, slots=True)
class Preferences:
    theme: str
    show_presence: bool


def get_preferences(session: Session, user_id: uuid.UUID) -> Preferences:
    """Return the user's stored preferences, or the defaults when no row exists."""
    row = session.execute(
        select(UserPreferences.theme, UserPreferences.show_presence).where(
            UserPreferences.user_id == user_id
        )
    ).one_or_none()

    if row is None:
        return Preferences(theme=DEFAULT_THEME, show_presence=DEFAULT_SHOW_PRESENCE)

    return Preferences(theme=row.theme, show_presence=row.show_presence)


def update_preferences(
    session: Session,
    user_id: uuid.UUID,
    *,
    theme: str | None = None,
    show_presence: bool | None = None,
) -> Preferences:
    """Upsert the provided preferences inside the caller's transaction.

    Only provided fields change on an existing row. A new row takes the defaults for
    omitted fields. The caller is responsible for committing or rolling back.
    """
    if theme is None and show_presence is None:
        raise ValueError("At least one preference must be provided.")

    insert_values = {
        "user_id": user_id,
        "theme": theme if theme is not None else DEFAULT_THEME,
        "show_presence": show_presence if show_presence is not None else DEFAULT_SHOW_PRESENCE,
    }
    update_values: dict[str, object] = {"updated_at": func.now()}
    if theme is not None:
        update_values["theme"] = theme
    if show_presence is not None:
        update_values["show_presence"] = show_presence

    statement = (
        insert(UserPreferences)
        .values(**insert_values)
        .on_conflict_do_update(index_elements=[UserPreferences.user_id], set_=update_values)
        .returning(UserPreferences.theme, UserPreferences.show_presence)
    )
    row = session.execute(statement).one()

    return Preferences(theme=row.theme, show_presence=row.show_presence)
