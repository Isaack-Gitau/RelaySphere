from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.api.v1.endpoints.auth import _enforce_rate_limit
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.users import (
    ChangeUsernameRequest,
    PreferencesResponse,
    UpdatePreferencesRequest,
    UpdateProfileRequest,
    UserProfileResponse,
)
from app.services.preferences import get_preferences, update_preferences
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


@router.get(
    "/me/preferences",
    response_model=PreferencesResponse,
    status_code=status.HTTP_200_OK,
)
def get_my_preferences(
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> PreferencesResponse:
    """Return the authenticated user's preferences, or the defaults."""
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
                scope="users:get-preferences:ip",
                kind="ip",
                identifier=client.host,
                limit=60,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="users:get-preferences:user",
                kind="email",
                identifier=normalized_email,
                limit=30,
                window_seconds=900,
            ),
        ],
    )

    try:
        preferences = get_preferences(session, current_user.id)
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    return PreferencesResponse(
        theme=preferences.theme,
        show_presence=preferences.show_presence,
    )


@router.patch(
    "/me/preferences",
    response_model=PreferencesResponse,
    status_code=status.HTTP_200_OK,
)
def update_my_preferences(
    request: UpdatePreferencesRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> PreferencesResponse:
    """Update the provided preferences and return the complete result."""
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
                scope="users:update-preferences:ip",
                kind="ip",
                identifier=client.host,
                limit=30,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="users:update-preferences:user",
                kind="email",
                identifier=normalized_email,
                limit=10,
                window_seconds=900,
            ),
        ],
    )

    try:
        preferences = update_preferences(
            session,
            current_user.id,
            theme=request.theme,
            show_presence=request.show_presence,
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    return PreferencesResponse(
        theme=preferences.theme,
        show_presence=preferences.show_presence,
    )
