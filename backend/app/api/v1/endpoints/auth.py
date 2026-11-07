import hmac
import uuid
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
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.dependencies.current_user import get_current_auth, get_current_user
from app.core.config import get_settings
from app.core.email_change import EMAIL_CHANGE_EMAIL_EVENT
from app.core.password_reset import PASSWORD_RESET_EMAIL_EVENT
from app.db.session import get_db_session
from app.models.refresh_session import RefreshSession, RefreshTokenHistory
from app.models.user import User
from app.schemas.auth import (
    CurrentUserResponse,
    EmailChangeConfirmRequest,
    EmailChangeConfirmResponse,
    EmailChangeStartRequest,
    EmailChangeStartResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LoginResponse,
    ReauthRequest,
    ReauthResponse,
    RegisterRequest,
    RegisterResponse,
    ResendVerificationRequest,
    ResendVerificationResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    RevokeOthersRequest,
    RevokeOthersResponse,
    SessionListResponse,
    SessionSummary,
    UsernameReservationReleaseRequest,
    UsernameReservationRequest,
    UsernameReservationResponse,
    UsernameSuggestionsRequest,
    UsernameSuggestionsResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from app.security.csrf import generate_csrf_token, validate_csrf_token
from app.security.tokens import create_access_token
from app.services.email_change import (
    EmailChangeError,
    confirm_email_change,
    request_email_change,
)
from app.services.email_outbox import enqueue_email
from app.services.email_verification import (
    EmailVerificationError,
    resend_verification_email,
    verify_email_token,
)
from app.services.login import (
    InvalidCredentialsError,
    authenticate_user,
    get_access_token_expiry_seconds,
    verify_reauth_password,
)
from app.services.password_reset import (
    PasswordResetError,
    confirm_password_reset,
    request_password_reset,
)
from app.services.rate_limiting import (
    RateLimitBucket,
    consume_rate_limit_buckets,
)
from app.services.refresh_sessions import (
    REAUTH_WINDOW,
    InvalidRefreshTokenError,
    RefreshTokenError,
    create_refresh_session,
    hash_refresh_token,
    is_recently_reauthenticated,
    revoke_refresh_session,
    rotate_refresh_token,
    session_is_expired,
)
from app.services.registration import (
    VERIFICATION_EMAIL_EVENT,
    EmailAlreadyRegisteredError,
    register_user_with_verification_token,
)
from app.services.username_reservations import (
    UsernameReservationExistsError,
    UsernameReservationExpiredError,
    UsernameReservationInvalidError,
    UsernameUnavailableError,
    create_username_reservation,
    release_username_reservation,
)
from app.services.username_suggestions import suggest_usernames

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
    session_id: str | uuid.UUID,
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
    "/username-reservations",
    response_model=UsernameReservationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_username_reservation_endpoint(
    request: UsernameReservationRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UsernameReservationResponse:
    """Reserve a username for a registration attempt."""
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
                scope="auth:username-reservations:create:ip",
                kind="ip",
                identifier=client.host,
                limit=10,
                window_seconds=900,
            )
        ],
    )

    try:
        with session.begin():
            created = create_username_reservation(
                session,
                request.username,
                request.registration_attempt_id,
            )
    except UsernameUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="USERNAME_UNAVAILABLE",
        ) from exc
    except UsernameReservationExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="USERNAME_RESERVATION_EXISTS",
        ) from exc
    except IntegrityError as exc:
        constraint_name = getattr(
            getattr(exc.orig, "diag", None),
            "constraint_name",
            None,
        )
        if constraint_name == "uq_username_claims_username":
            detail = "USERNAME_UNAVAILABLE"
        elif constraint_name == "uq_username_claims_reservation_attempt":
            detail = "USERNAME_RESERVATION_EXISTS"
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service temporarily unavailable.",
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    return UsernameReservationResponse(
        reservation_id=created.reservation_id,
        username=created.username,
        reservation_token=created.reservation_token,
        expires_at=created.expires_at,
    )


@router.post(
    "/username-suggestions",
    response_model=UsernameSuggestionsResponse,
    status_code=status.HTTP_200_OK,
)
def username_suggestions_endpoint(
    request: UsernameSuggestionsRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> UsernameSuggestionsResponse:
    """Return available username suggestions without reserving them."""
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
                scope="auth:username-suggestions:ip",
                kind="ip",
                identifier=client.host,
                limit=30,
                window_seconds=3600,
            ),
        ],
    )

    try:
        suggestions = suggest_usernames(session, request.display_name)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        ) from exc

    return UsernameSuggestionsResponse(suggestions=suggestions)


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
    """Register an account and queue its verification email atomically."""
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

    try:
        register_user_with_verification_token(session, registration)
        session.commit()
    except EmailAlreadyRegisteredError:
        session.rollback()
    except Exception:
        session.rollback()
        raise

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
    """Queue a replacement verification email without revealing account status."""
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

    try:
        resend_result = resend_verification_email(session, normalized_email)
        if resend_result is not None:
            user, raw_token = resend_result
            enqueue_email(
                session,
                VERIFICATION_EMAIL_EVENT,
                {
                    "recipient": user.email,
                    "display_name": user.display_name,
                    "verification_token": raw_token,
                },
            )
        session.commit()
    except Exception:
        session.rollback()
        raise

    return ResendVerificationResponse(
        message="If an eligible account exists, a verification email will be sent shortly."
    )


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> ForgotPasswordResponse:
    """Queue a password reset email without revealing account status."""
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
                scope="auth:forgot-password:ip",
                kind="ip",
                identifier=client.host,
                limit=5,
                window_seconds=3600,
            ),
            RateLimitBucket(
                scope="auth:forgot-password:ip-email",
                kind="email",
                identifier=f"{client.host}\\0{normalized_email}",
                limit=3,
                window_seconds=3600,
            ),
        ],
    )

    try:
        reset_result = request_password_reset(session, normalized_email)
        if reset_result is not None:
            user, raw_token = reset_result
            enqueue_email(
                session,
                PASSWORD_RESET_EMAIL_EVENT,
                {
                    "recipient": user.email,
                    "display_name": user.display_name,
                    "password_reset_token": raw_token,
                },
            )
        session.commit()
    except Exception:
        session.rollback()
        raise

    return ForgotPasswordResponse(
        message="If an eligible account exists, a password reset email will be sent shortly."
    )


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=status.HTTP_200_OK,
)
def reset_password(
    request: ResetPasswordRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> ResetPasswordResponse:
    """Set a new password using a reset token and revoke every session."""
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
                scope="auth:reset-password:ip",
                kind="ip",
                identifier=client.host,
                limit=10,
                window_seconds=900,
            ),
        ],
    )

    try:
        confirm_password_reset(session, request.token, request.new_password)
        session.commit()
    except PasswordResetError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    return ResetPasswordResponse(
        message="Password reset successfully. Please log in with your new password."
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
        refresh_token = create_refresh_session(session, user.id, reauthenticated=True)
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


@router.post(
    "/reauth",
    response_model=ReauthResponse,
    status_code=status.HTTP_200_OK,
)
def reauthenticate(
    request: ReauthRequest,
    http_request: Request,
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> ReauthResponse:
    """Confirm the password and start a fixed 10-minute reauthentication window."""
    user, current_session = auth
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = user.email.strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:reauth:ip",
                kind="ip",
                identifier=client.host,
                limit=20,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="auth:reauth:user",
                kind="email",
                identifier=normalized_email,
                limit=5,
                window_seconds=900,
            ),
        ],
    )

    if not verify_reauth_password(user, request.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid_credentials",
        )

    try:
        record = session.scalar(
            select(RefreshSession)
            .where(RefreshSession.id == current_session.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        now = datetime.now(UTC)
        if record is None or record.revoked_at is not None:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        record.reauthenticated_at = now
        session.commit()
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        raise

    return ReauthResponse(reauthenticated_until=now + REAUTH_WINDOW)


@router.post(
    "/sessions/revoke-others",
    response_model=RevokeOthersResponse,
    status_code=status.HTTP_200_OK,
)
def revoke_other_sessions(
    request: RevokeOthersRequest,
    http_request: Request,
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> RevokeOthersResponse:
    """Revoke every other active session of the user and keep the current one."""
    user, current_session = auth
    client = http_request.client
    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = user.email.strip().casefold()
    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:revoke-others:ip",
                kind="ip",
                identifier=client.host,
                limit=20,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="auth:revoke-others:user",
                kind="email",
                identifier=normalized_email,
                limit=5,
                window_seconds=900,
            ),
        ],
    )

    try:
        # Lock every active session of this user in a stable order so two
        # concurrent revoke-others calls cannot deadlock each other.
        active_sessions = session.scalars(
            select(RefreshSession)
            .where(
                RefreshSession.user_id == user.id,
                RefreshSession.revoked_at.is_(None),
            )
            .order_by(RefreshSession.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).all()
        now = datetime.now(UTC)
        current = next((s for s in active_sessions if s.id == current_session.id), None)
        if current is None:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not is_recently_reauthenticated(current.reauthenticated_at, now):
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="reauthentication_required",
            )
        others = [s for s in active_sessions if s.id != current.id]
        for other in others:
            other.revoked_at = now
        session.commit()
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        raise

    return RevokeOthersResponse(revoked_count=len(others))


_SESSION_LIST_LIMIT = 50


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    status_code=status.HTTP_200_OK,
)
def list_sessions(
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> SessionListResponse:
    """List the caller's active sessions, current session first."""
    user, current_session = auth
    now = datetime.now(UTC)
    candidates = session.scalars(
        select(RefreshSession).where(
            RefreshSession.user_id == user.id,
            RefreshSession.revoked_at.is_(None),
            RefreshSession.expires_at > now,
        )
    ).all()
    active = [record for record in candidates if not session_is_expired(record, now)]

    def sort_key(record: RefreshSession) -> tuple[bool, datetime]:
        return (record.id == current_session.id, record.last_used_at or record.created_at)

    active.sort(key=sort_key, reverse=True)

    items = []
    for record in active[:_SESSION_LIST_LIMIT]:
        marker = record.reauthenticated_at
        reauthenticated_until = None
        if marker is not None and is_recently_reauthenticated(marker, now):
            if marker.tzinfo is None:
                marker = marker.replace(tzinfo=UTC)
            reauthenticated_until = marker + REAUTH_WINDOW
        items.append(
            SessionSummary(
                id=record.id,
                created_at=record.created_at,
                last_used_at=record.last_used_at,
                expires_at=record.expires_at,
                reauthenticated_until=reauthenticated_until,
                is_current=record.id == current_session.id,
            )
        )

    return SessionListResponse(sessions=items)


@router.post(
    "/email-change/request",
    response_model=EmailChangeStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def start_email_change(
    request: EmailChangeStartRequest,
    http_request: Request,
    auth: tuple[User, RefreshSession] = Depends(get_current_auth),  # noqa: B008
    session: Session = Depends(get_db_session),  # noqa: B008
) -> EmailChangeStartResponse:
    """Request an email change after recent reauthentication."""
    user, current_session = auth
    client = http_request.client

    if client is None or not client.host:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable.",
        )

    normalized_email = user.email.strip().casefold()

    _enforce_rate_limit(
        http_request,
        [
            RateLimitBucket(
                scope="auth:email-change-request:ip",
                kind="ip",
                identifier=client.host,
                limit=10,
                window_seconds=900,
            ),
            RateLimitBucket(
                scope="auth:email-change-request:user",
                kind="email",
                identifier=normalized_email,
                limit=5,
                window_seconds=900,
            ),
        ],
    )

    try:
        # Preserve the email-change service's lock order:
        # user first, then the current refresh session.
        locked_user = session.scalar(
            select(User)
            .where(User.id == user.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

        if locked_user is None or not locked_user.is_active:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        current = session.scalar(
            select(RefreshSession)
            .where(
                RefreshSession.id == current_session.id,
                RefreshSession.user_id == locked_user.id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )

        now = datetime.now(UTC)

        if current is None or current.revoked_at is not None or session_is_expired(current, now):
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not is_recently_reauthenticated(current.reauthenticated_at, now):
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="reauthentication_required",
            )

        result = request_email_change(
            session,
            locked_user.id,
            str(request.new_email),
        )

        if result is not None:
            requested_user, new_email, raw_token = result

            enqueue_email(
                session,
                EMAIL_CHANGE_EMAIL_EVENT,
                {
                    "recipient": new_email,
                    "display_name": requested_user.display_name,
                    "email_change_token": raw_token,
                },
            )

        # The request record and encrypted outbox job commit atomically.
        session.commit()

    except HTTPException:
        raise
    except Exception:
        session.rollback()
        raise

    return EmailChangeStartResponse(
        message="If the address is eligible, a confirmation email will be sent shortly."
    )


@router.post(
    "/email-change/confirm",
    response_model=EmailChangeConfirmResponse,
    status_code=status.HTTP_200_OK,
)
def confirm_email_change_endpoint(
    request: EmailChangeConfirmRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> EmailChangeConfirmResponse:
    """Confirm an email change and revoke the account's active sessions."""
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
                scope="auth:email-change-confirm:ip",
                kind="ip",
                identifier=client.host,
                limit=10,
                window_seconds=900,
            ),
        ],
    )

    try:
        confirm_email_change(session, request.token)
        session.commit()
    except EmailChangeError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired confirmation token.",
        ) from exc
    except Exception:
        session.rollback()
        raise

    return EmailChangeConfirmResponse(
        message="Email address updated successfully. Please sign in again."
    )


@router.delete(
    "/username-reservations/{reservation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def release_username_reservation_endpoint(
    reservation_id: uuid.UUID,
    request: UsernameReservationReleaseRequest,
    http_request: Request,
    session: Session = Depends(get_db_session),  # noqa: B008
) -> Response:
    """Release a username reservation using its attempt ID and one-time token."""
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
                scope="auth:username-reservations:release:ip",
                kind="ip",
                identifier=client.host,
                limit=20,
                window_seconds=900,
            ),
        ],
    )

    try:
        release_username_reservation(
            session,
            reservation_id,
            request.registration_attempt_id,
            request.reservation_token,
        )
        session.commit()
    except UsernameReservationInvalidError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="USERNAME_RESERVATION_INVALID",
        ) from exc
    except UsernameReservationExpiredError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="USERNAME_RESERVATION_EXPIRED",
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

    return Response(status_code=status.HTTP_204_NO_CONTENT)
