import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.api.v1.endpoints.auth import _enforce_rate_limit
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.user_discovery import UserDirectoryEntry, UserSearchResponse
from app.services.rate_limiting import RateLimitBucket
from app.services.user_discovery import (
    InvalidCursorError,
    InvalidQueryError,
    decode_cursor,
    get_eligible_user,
    normalize_query,
    search_users,
)

SEARCH_USER_LIMIT = 120
SEARCH_IP_LIMIT = 300
LOOKUP_USER_LIMIT = 60
LOOKUP_IP_LIMIT = 120
RATE_LIMIT_WINDOW_SECONDS = 900

router = APIRouter(prefix="/users", tags=["Users"])


def _client_host(http_request: Request) -> str:
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )
    return client.host


def _buckets(
    prefix: str,
    host: str,
    user: User,
    user_limit: int,
    ip_limit: int,
) -> list[RateLimitBucket]:
    return [
        RateLimitBucket(
            scope=f"users:{prefix}:ip",
            kind="ip",
            identifier=host,
            limit=ip_limit,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        ),
        RateLimitBucket(
            scope=f"users:{prefix}:user",
            kind="email",
            identifier=user.email.strip().casefold(),
            limit=user_limit,
            window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        ),
    ]


@router.get("", response_model=UserSearchResponse)
def search_users_endpoint(
    http_request: Request,
    q: Annotated[str, Query(max_length=200)],
    current_user: User = Depends(get_current_user),  # noqa: B008
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UserSearchResponse:
    """Search eligible users by username or display-name prefix."""
    try:
        query = normalize_query(q)
    except InvalidQueryError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="INVALID_QUERY",
        ) from None

    position = None
    if cursor is not None:
        try:
            position = decode_cursor(cursor)
        except InvalidCursorError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="INVALID_CURSOR",
            ) from None

    host = _client_host(http_request)
    _enforce_rate_limit(
        http_request,
        _buckets("search", host, current_user, SEARCH_USER_LIMIT, SEARCH_IP_LIMIT),
    )

    try:
        page = search_users(session, current_user.id, query, limit, position)
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    return UserSearchResponse(
        items=[
            UserDirectoryEntry(id=item.id, username=item.username, display_name=item.display_name)
            for item in page.items
        ],
        next_cursor=page.next_cursor,
    )


@router.get("/{user_id}", response_model=UserDirectoryEntry)
def get_user_endpoint(
    user_id: uuid.UUID,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UserDirectoryEntry:
    """Return the public entry for one eligible user."""
    host = _client_host(http_request)
    _enforce_rate_limit(
        http_request,
        _buckets("get", host, current_user, LOOKUP_USER_LIMIT, LOOKUP_IP_LIMIT),
    )

    try:
        entry = get_eligible_user(session, user_id)
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return UserDirectoryEntry(id=entry.id, username=entry.username, display_name=entry.display_name)
