import hmac
from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_user
from app.core.config import get_settings
from app.db.session import get_db_session
from app.integrations.email_delivery import send_verification_email
from app.models.refresh_session import RefreshSession, RefreshTokenHistory
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResendVerificationResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from app.security.csrf import generate_csrf_token, validate_csrf_token
from app.security.tokens import create_access_token
from app.services.email_verification import (
    EmailVerificationError,
    resend_verification_token,
    verify_email_token,
)
from app.services.login import (
    InvalidCredentialsError,
    authenticate_user,
    get_access_token_expiry_seconds,
)
from app.services.rate_limiting import (
    RateLimitBucket,
    consume_rate_limit_buckets,
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


def _enforce_rate_limit(
    http_request: Request,
    buckets: list[RateLimitBucket],
) -> None:
    """Enforce rate limits using the direct ASGI client address."""
    client = http_request.client

    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    try:
        result = consume_rate_limit_buckets(buckets)
    except SQLAlchemyError as exc:
        # Authentication must fail closed if the persistent limiter is unavailable.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(result.retry_after_seconds or 1)},
        )


def _auth_cookie_path() -> str:
    """Return the cookie path for the configured authentication API prefix."""
    api_prefix = get_settings().api_v1_prefix.rstrip("/")
    return f"{api_prefix}/auth"


def _refresh_cookie_max_age(expires_at: datetime) -> int:
    """Return the remaining lifetime of a persisted refresh session."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)

    remaining_seconds = (expires_at - datetime.now(UTC)).total_seconds()
    return max(0, int(remaining_seconds))


def _set_csrf_cookie(response: Response, csrf_token: str, expires_at: datetime) -> None:
    settings = get_settings()
    response.set_cookie(
        key="relaysphere_csrf",
        value=csrf_token,
        max_age=_refresh_cookie_max_age(expires_at),
        httponly=False,
        secure=settings.environment.lower() not in {"development", "testing"},
        samesite="lax",
        path=_auth_cookie_path(),
    )


def _clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    secure = settings.environment.lower() not in {"development", "testing"}
    response.delete_cookie(
        key="relaysphere_refresh",
        path=_auth_cookie_path(),
        httponly=True,
        secure=secure,
        samesite="lax",
    )
    response.delete_cookie(
        key="relaysphere_csrf",
        path=_auth_cookie_path(),
        httponly=False,
        secure=secure,
        samesite="lax",
    )


def _require_csrf(
    csrf_cookie: str | None,
    csrf_header: str | None,
    session_id: object,
) -> None:
    if (
        not csrf_cookie
        or not csrf_header
        or not hmac.compare_digest(csrf_cookie, csrf_header)
        or not validate_csrf_token(csrf_cookie, session_id)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def register(
    registration: RegisterRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> RegisterResponse:
    """Register an account without revealing whether its email already exists."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:register:ip",
                kind="ip",
                identifier=client.host,
                limit=5,
                window_seconds=3600,
            ),
        ],
    )

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
    except EmailAlreadyRegisteredError:
        return RegisterResponse(
            message=(
                "If an account can be created with this email, "
                "a verification email will be sent shortly."
            )
        )

    send_verification_email(user.email, raw_token)
    return RegisterResponse(
        message=(
            "If an account can be created with this email, "
            "a verification email will be sent shortly."
        )
    )


@router.post(
    "/resend-verification",
    response_model=ResendVerificationResponse,
    status_code=status.HTTP_200_OK,
)
def resend_verification(
    request: ResendVerificationRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> ResendVerificationResponse:
    """Resend verification email without revealing account status."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = str(request.email).strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:resend-verification:ip",
                kind="ip",
                identifier=client.host,
                limit=5,
                window_seconds=3600,
            ),
            RateLimitBucket(
                scope="auth:resend-verification:ip-email",
                kind="email",
                identifier=f"{client.host}\\0{normalized_email}",
                limit=3,
                window_seconds=3600,
            ),
        ],
    )

    settings = get_settings()

    if settings.environment.lower() not in {"development", "testing"}:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification delivery is not configured for this environment.",
        )

    try:
        raw_token = resend_verification_token(session, str(request.email))
        session.commit()
    except Exception:
        session.rollback()
        raise

    if raw_token is not None:
        send_verification_email(str(request.email), raw_token)

    return ResendVerificationResponse(
        message="If an eligible account exists, a verification email will be sent shortly."
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    request: LoginRequest,
    response: Response,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> LoginResponse:
    """Authenticate an account and issue access and refresh credentials."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = str(request.email).strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:login:ip",
                kind="ip",
                identifier=client.host,
                limit=20,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="auth:login:ip-email",
                kind="email",
                identifier=f"{client.host}\\0{normalized_email}",
                limit=5,
                window_seconds=900,
            ),
        ],
    )

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
        csrf_token = generate_csrf_token(refresh_record.id)
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
        path=_auth_cookie_path(),
    )
    _set_csrf_cookie(response, csrf_token, session_expires_at)

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
    relaysphere_csrf: str | None = Cookie(default=None),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    session: Session = Depends(get_db_session),  # noqa: B008
) -> LoginResponse:
    """Rotate the refresh cookie and issue a new access token."""
    settings = get_settings()

    def clear_refresh_cookie() -> None:
        _clear_auth_cookies(response)

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
        if refresh_record is not None:
            session_id = refresh_record.id
        else:
            consumed_record = session.scalar(
                select(RefreshTokenHistory).where(RefreshTokenHistory.token_hash == current_hash)
            )
            if consumed_record is None:
                # Unknown tokens remain generic and cannot identify a session.
                rotate_refresh_token(session, relaysphere_refresh)
                raise InvalidRefreshTokenError("Invalid refresh token.")
            session_id = consumed_record.session_id

        # Validate before rotation so a failed CSRF check cannot revoke a session.
        _require_csrf(relaysphere_csrf, csrf_header, session_id)

        if refresh_record is None:
            # A valid CSRF token allows the service to detect and revoke replay.
            rotate_refresh_token(session, relaysphere_refresh)
            raise InvalidRefreshTokenError("Invalid refresh token.")

        user_id = refresh_record.user_id
        session_expires_at = refresh_record.expires_at

        new_refresh_token = rotate_refresh_token(
            session,
            relaysphere_refresh,
        )

        new_access_token = create_access_token(
            subject=str(user_id),
            session_id=str(session_id),
        )
        csrf_token = generate_csrf_token(session_id)
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
        path=_auth_cookie_path(),
    )
    _set_csrf_cookie(response, csrf_token, session_expires_at)

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
    relaysphere_csrf: str | None = Cookie(default=None),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    session: Session = Depends(get_db_session),  # noqa: B008
) -> dict[str, str]:
    """Revoke the current refresh session and clear its browser cookie."""
    try:
        if relaysphere_refresh:
            current_hash = hash_refresh_token(relaysphere_refresh)
            refresh_record = session.scalar(
                select(RefreshSession).where(RefreshSession.token_hash == current_hash)
            )

            if refresh_record is not None:
                # Active tokens require proof of possession before revocation.
                _require_csrf(relaysphere_csrf, csrf_header, refresh_record.id)
                revoke_refresh_session(session, relaysphere_refresh)
            else:
                consumed_record = session.scalar(
                    select(RefreshTokenHistory).where(
                        RefreshTokenHistory.token_hash == current_hash
                    )
                )

                if consumed_record is not None:
                    # A consumed token can identify its session only after CSRF validation.
                    _require_csrf(
                        relaysphere_csrf,
                        csrf_header,
                        consumed_record.session_id,
                    )

                    try:
                        # Reuse detection revokes the associated session.
                        rotate_refresh_token(session, relaysphere_refresh)
                    except RefreshTokenError as exc:
                        if exc.commit_required:
                            session.commit()
                        else:
                            session.rollback()
                else:
                    # Unknown tokens cannot identify a session and remain generic.
                    session.rollback()

        session.commit()
    except Exception:
        session.rollback()
        raise

    _clear_auth_cookies(response)

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
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> VerifyEmailResponse:
    """Verify an email address using a valid verification token."""
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:verify-email:ip",
                kind="ip",
                identifier=client.host,
                limit=10,
                window_seconds=900,
            ),
        ],
    )

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
