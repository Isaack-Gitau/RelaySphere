from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.security.tokens import decode_access_token
from app.services.refresh_sessions import is_recently_reauthenticated, session_is_expired

_bearer_scheme = HTTPBearer(auto_error=False)


def _authentication_error() -> HTTPException:
    """Return a consistent response for unauthenticated requests."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(  # noqa: B008
        _bearer_scheme
    ),
    session: Session = Depends(get_db_session),  # noqa: B008
) -> tuple[User, RefreshSession]:
    """Resolve a bearer token to its user and active server-managed session."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _authentication_error()

    try:
        claims = decode_access_token(credentials.credentials)
        user_id = UUID(claims["sub"])
        session_id = UUID(claims["sid"])
    except (ValueError, KeyError, TypeError):
        raise _authentication_error() from None

    refresh_session = session.scalar(select(RefreshSession).where(RefreshSession.id == session_id))
    now = datetime.now(UTC)

    if (
        refresh_session is None
        or refresh_session.user_id != user_id
        or refresh_session.revoked_at is not None
        or session_is_expired(refresh_session, now)
    ):
        raise _authentication_error()

    user = session.scalar(select(User).where(User.id == user_id))

    if user is None or not user.is_active or user.email_verified_at is None:
        raise _authentication_error()

    # Do not commit unrelated pending ORM changes from other dependencies.
    # If the shared session is clean, persist this request's activity timestamp
    # before the endpoint handler executes.
    if not session.new and not session.dirty and not session.deleted:
        refresh_session.last_used_at = now
        session.commit()

    return user, refresh_session


def get_current_user(
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
) -> User:
    """Resolve a bearer token to its authenticated user."""
    return auth[0]


def require_recent_reauth(
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
) -> User:
    """Require a session that re-entered its password within the last 10 minutes."""
    user, refresh_session = auth
    if not is_recently_reauthenticated(refresh_session.reauthenticated_at, datetime.now(UTC)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="reauthentication_required",
        )
    return user
