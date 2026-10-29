from datetime import UTC, datetime

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.core.config import get_settings
from app.db.session import get_db_session
from app.integrations.email_delivery import send_verification_email
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from app.security.tokens import create_access_token
from app.services.email_verification import (
    EmailVerificationError,
    verify_email_token,
)
from app.services.login import (
    InvalidCredentialsError,
    authenticate_user,
    get_access_token_expiry_seconds,
)
from app.services.refresh_sessions import (
    InvalidRefreshTokenError,
    RefreshTokenError,
    create_refresh_session,
    hash_refresh_token,
    revoke_refresh_session,
    rotate_refresh_token,
)
from app.services.registration import (
    EmailAlreadyRegisteredError,
    register_user_with_verification_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _refresh_cookie_max_age(expires_at: datetime) -> int:
    """Return the remaining lifetime of a persisted refresh session."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)

    remaining_seconds = (expires_at - datetime.now(UTC)).total_seconds()
    return max(0, int(remaining_seconds))


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    registration: RegisterRequest,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> RegisterResponse:
    """Register an account and deliver its email verification token."""
    settings = get_settings()

    if settings.environment.lower() not in {"development", "testing"}:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification delivery is not configured for this environment.",
        )

    try:
        user, raw_token = register_user_with_verification_token(
            session,
            registration,
        )
    except EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to register with the supplied email address.",
        ) from exc

    send_verification_email(user.email, raw_token)
    return RegisterResponse.model_validate(user)


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    request: LoginRequest,
    response: Response,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> LoginResponse:
    """Authenticate an account and issue access and refresh credentials."""
    try:
        user = authenticate_user(session, request)
        refresh_token = create_refresh_session(session, user.id)
        refresh_record = session.scalar(
            select(RefreshSession).where(
                RefreshSession.token_hash == hash_refresh_token(refresh_token)
            )
        )
        if refresh_record is None:
            raise RuntimeError("Created refresh session could not be loaded.")
        session_expires_at = refresh_record.expires_at
        access_token = create_access_token(
            subject=str(user.id),
            session_id=str(refresh_record.id),
        )
        session.commit()
    except InvalidCredentialsError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except Exception:
        session.rollback()
        raise

    settings = get_settings()
    response.set_cookie(
        key="relaysphere_refresh",
        value=refresh_token,
        max_age=_refresh_cookie_max_age(session_expires_at),
        httponly=True,
        secure=settings.environment.lower() not in {"development", "testing"},
        samesite="lax",
        path="/api/v1/auth",
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=get_access_token_expiry_seconds(),
    )


@router.post(
    "/refresh",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def refresh_access_token(
    response: Response,
    relaysphere_refresh: str | None = Cookie(default=None),
    session: Session = Depends(get_db_session),  # noqa: B008
) -> LoginResponse:
    """Rotate the refresh cookie and issue a new access token."""
    settings = get_settings()

    def clear_refresh_cookie() -> None:
        response.delete_cookie(
            key="relaysphere_refresh",
            path="/api/v1/auth",
            httponly=True,
            secure=settings.environment.lower() not in {"development", "testing"},
            samesite="lax",
        )

    if not relaysphere_refresh:
        clear_refresh_cookie()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh session.",
        )

    try:
        current_hash = hash_refresh_token(relaysphere_refresh)
        refresh_record = session.scalar(
            select(RefreshSession).where(RefreshSession.token_hash == current_hash)
        )
        if refresh_record is None:
            # Let the service distinguish a replayed token from an unknown token.
            # Replays must reach the session-revocation path.
            rotate_refresh_token(session, relaysphere_refresh)
            raise InvalidRefreshTokenError("Invalid refresh token.")
        user_id = refresh_record.user_id
        session_id = refresh_record.id
        session_expires_at = refresh_record.expires_at

        new_refresh_token = rotate_refresh_token(
            session,
            relaysphere_refresh,
        )

        new_access_token = create_access_token(
            subject=str(user_id),
            session_id=str(session_id),
        )
        session.commit()
    except RefreshTokenError as exc:
        try:
            if exc.commit_required:
                session.commit()
            else:
                session.rollback()
        except Exception:
            session.rollback()
            raise

        clear_refresh_cookie()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh session.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    response.set_cookie(
        key="relaysphere_refresh",
        value=new_refresh_token,
        max_age=_refresh_cookie_max_age(session_expires_at),
        httponly=True,
        secure=settings.environment.lower() not in {"development", "testing"},
        samesite="lax",
        path="/api/v1/auth",
    )

    return LoginResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=get_access_token_expiry_seconds(),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
)
def logout(
    response: Response,
    relaysphere_refresh: str | None = Cookie(default=None),
    session: Session = Depends(get_db_session),  # noqa: B008
) -> dict[str, str]:
    """Revoke the current refresh session and clear its browser cookie."""
    settings = get_settings()

    try:
        if relaysphere_refresh:
            try:
                revoke_refresh_session(session, relaysphere_refresh)
            except InvalidRefreshTokenError:
                # Invalid cookies must not reveal whether a session exists.
                session.rollback()

        session.commit()
    except Exception:
        session.rollback()
        raise

    response.delete_cookie(
        key="relaysphere_refresh",
        path="/api/v1/auth",
        httponly=True,
        secure=settings.environment.lower() not in {"development", "testing"},
        samesite="lax",
    )

    return {"message": "Logged out."}


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    status_code=status.HTTP_200_OK,
)
def get_me(
    current_user: User = Depends(get_current_user),  # noqa: B008
) -> CurrentUserResponse:
    """Return the authenticated user's safe account details."""
    return CurrentUserResponse.model_validate(current_user)


@router.post(
    "/verify-email",
    response_model=VerifyEmailResponse,
    status_code=status.HTTP_200_OK,
)
def verify_email(
    request: VerifyEmailRequest,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> VerifyEmailResponse:
    """Verify an email address using a valid verification token."""
    try:
        user = verify_email_token(session, request.token)
        session.commit()
    except EmailVerificationError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    if user.email_verified_at is None:
        raise RuntimeError("Email verification completed without a timestamp.")

    return VerifyEmailResponse(
        message="Email verified successfully.",
        email_verified_at=user.email_verified_at,
    )
