from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.api.v1.endpoints.auth import _enforce_rate_limit
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.users import ChangeUsernameRequest, UpdateProfileRequest, UserProfileResponse
from app.services.rate_limiting import RateLimitBucket
from app.services.username_change import UsernameChangeCooldownError, change_username
from app.services.username_reservations import UsernameUnavailableError

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserProfileResponse,
    status_code=status.HTTP_200_OK,
)
def get_my_profile(
    current_user: User = Depends(get_current_user),  # noqa: B008
) -> UserProfileResponse:
    """Return the authenticated user's own profile."""
    return UserProfileResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserProfileResponse,
    status_code=status.HTTP_200_OK,
)
def update_my_profile(
    request: UpdateProfileRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UserProfileResponse:
    """Update the editable fields of the authenticated user's profile."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = current_user.email.strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="users:update-me:ip",
                kind="ip",
                identifier=client.host,
                limit=30,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="users:update-me:user",
                kind="email",
                identifier=normalized_email,
                limit=10,
                window_seconds=900,
            ),
        ],
    )

    try:
        current_user.display_name = request.display_name
        session.commit()
    except Exception:
        session.rollback()
        raise

    return UserProfileResponse.model_validate(current_user)


@router.put(
    "/me/username",
    response_model=UserProfileResponse,
    status_code=status.HTTP_200_OK,
)
def change_my_username(
    request: ChangeUsernameRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UserProfileResponse:
    """Move the authenticated user to a new permanent username."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = current_user.email.strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="users:change-username:ip",
                kind="ip",
                identifier=client.host,
                limit=20,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="users:change-username:user",
                kind="email",
                identifier=normalized_email,
                limit=5,
                window_seconds=900,
            ),
        ],
    )

    try:
        change_username(session, current_user.id, request.username)
        session.commit()
    except UsernameChangeCooldownError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="USERNAME_CHANGE_COOLDOWN",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except UsernameUnavailableError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="USERNAME_UNAVAILABLE",
        ) from exc
    except IntegrityError as exc:
        session.rollback()
        constraint_name = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        if constraint_name == "uq_username_claims_username":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="USERNAME_UNAVAILABLE",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    return UserProfileResponse.model_validate(current_user)
