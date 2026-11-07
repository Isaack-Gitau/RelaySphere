from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.api.v1.endpoints.auth import _enforce_rate_limit
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.users import UpdateProfileRequest, UserProfileResponse
from app.services.rate_limiting import RateLimitBucket

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
