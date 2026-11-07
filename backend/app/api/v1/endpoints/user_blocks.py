import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.api.v1.endpoints.auth import _enforce_rate_limit
from app.api.v1.endpoints.user_discovery import _buckets, _client_host
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.user_blocks import BlockedUsersResponse
from app.schemas.user_discovery import UserDirectoryEntry
from app.services.user_blocks import (
    InvalidBlockCursorError,
    block_user,
    decode_block_cursor,
    list_blocked_users,
    unblock_user,
)
from app.services.user_discovery import get_eligible_user

BLOCK_USER_LIMIT = 30
BLOCK_IP_LIMIT = 60
LIST_USER_LIMIT = 60
LIST_IP_LIMIT = 120

router = APIRouter(prefix="/users", tags=["Users"])


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Service temporarily unavailable.",
    )


@router.put(
    "/{user_id}/block",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def block_user_endpoint(
    user_id: uuid.UUID,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> Response:
    """Block another eligible user. Repeating the request changes nothing."""
    host = _client_host(http_request)
    _enforce_rate_limit(
        http_request,
        _buckets("block", host, current_user, BLOCK_USER_LIMIT, BLOCK_IP_LIMIT),
    )

    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="CANNOT_BLOCK_SELF",
        )

    try:
        # Eligibility is checked without the block filter so the answer never
        # reveals whether the other user has blocked the caller.
        target = get_eligible_user(session, user_id)
        if target is not None:
            block_user(session, current_user.id, user_id)
            session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        ) from exc
    except SQLAlchemyError as exc:
        session.rollback()
        raise _unavailable() from exc
    except Exception:
        session.rollback()
        raise

    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/{user_id}/block",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def unblock_user_endpoint(
    user_id: uuid.UUID,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> Response:
    """Remove the caller's block. The answer is the same whether or not one existed."""
    host = _client_host(http_request)
    _enforce_rate_limit(
        http_request,
        _buckets("unblock", host, current_user, BLOCK_USER_LIMIT, BLOCK_IP_LIMIT),
    )

    try:
        unblock_user(session, current_user.id, user_id)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise _unavailable() from exc
    except Exception:
        session.rollback()
        raise

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me/blocks", response_model=BlockedUsersResponse)
def list_my_blocks_endpoint(
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> BlockedUsersResponse:
    """List the eligible users the caller has blocked, newest first."""
    position = None
    if cursor is not None:
        try:
            position = decode_block_cursor(cursor)
        except InvalidBlockCursorError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="INVALID_CURSOR",
            ) from None

    host = _client_host(http_request)
    _enforce_rate_limit(
        http_request,
        _buckets("list-blocks", host, current_user, LIST_USER_LIMIT, LIST_IP_LIMIT),
    )

    try:
        page = list_blocked_users(session, current_user.id, limit, position)
    except SQLAlchemyError as exc:
        session.rollback()
        raise _unavailable() from exc

    return BlockedUsersResponse(
        items=[
            UserDirectoryEntry(id=item.id, username=item.username, display_name=item.display_name)
            for item in page.items
        ],
        next_cursor=page.next_cursor,
    )
