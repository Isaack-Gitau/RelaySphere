import base64
import json
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.block import Block
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.security import tokens
from app.services.rate_limiting import RateLimitResult
from app.services.refresh_sessions import create_refresh_session, hash_refresh_token
from app.services.user_blocks import (
    InvalidBlockCursorError,
    decode_block_cursor,
    encode_block_cursor,
)

_BASE = "/api/v1/users"
_BLOCKS = _BASE + "/me/blocks"


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    def override_db_session() -> Generator[Session]:
        yield db_session

    app.dependency_overrides[get_db_session] = override_db_session
    try:
        with TestClient(app, headers={"Origin": "http://localhost:5173"}) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.fixture(autouse=True)
def token_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tokens,
        "get_settings",
        lambda: SimpleNamespace(
            access_token_secret="integration-test-secret-at-least-32-characters",
            access_token_expire_minutes=15,
        ),
    )


def _make_user(
    db_session: Session,
    *,
    username: bool = True,
    active: bool = True,
    verified: bool = True,
) -> User:
    user = User(
        email=f"blocks-{uuid.uuid4().hex}@example.com",
        display_name="Block Test",
        password_hash=None,
        is_active=active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    db_session.add(user)
    db_session.flush()

    if username:
        name = f"blk_{uuid.uuid4().hex[:8]}"
        db_session.add(UsernameClaim(username=name, claim_type="permanent", user_id=user.id))
        db_session.flush()
        db_session.expire(user, ["username_claim"])

    return user


def _auth_headers(db_session: Session, user: User) -> dict[str, str]:
    raw_token = create_refresh_session(db_session, user.id)
    record = db_session.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(raw_token))
    )
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    db_session.flush()
    access_token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return {"Authorization": f"Bearer {access_token}"}


def _block(
    db_session: Session,
    blocker: User,
    blocked: User,
    created_at: datetime | None = None,
) -> None:
    values: dict[str, object] = {"blocker_id": blocker.id, "blocked_id": blocked.id}
    if created_at is not None:
        values["created_at"] = created_at
    db_session.add(Block(**values))
    db_session.flush()


def _blocked_ids(db_session: Session, blocker: User) -> set[uuid.UUID]:
    return set(
        db_session.scalars(select(Block.blocked_id).where(Block.blocker_id == blocker.id)).all()
    )


def _raw_cursor(payload: object) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(data.encode("ascii")).decode("ascii").rstrip("=")


def _search_ids(api_client: TestClient, headers: dict[str, str], q: str) -> set[str]:
    response = api_client.get(_BASE, params={"q": q}, headers=headers)
    assert response.status_code == 200
    return {item["id"] for item in response.json()["items"]}


# ------------------------------------------------------------------ PUT


def test_put_block_creates_the_block(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)

    response = api_client.put(
        f"{_BASE}/{target.id}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 204
    assert response.content == b""
    assert _blocked_ids(db_session, caller) == {target.id}
    assert _blocked_ids(db_session, target) == set()


def test_put_block_is_idempotent(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    first = api_client.put(f"{_BASE}/{target.id}/block", headers=headers)
    second = api_client.put(f"{_BASE}/{target.id}/block", headers=headers)

    assert first.status_code == 204
    assert second.status_code == 204
    count = db_session.scalar(
        select(func.count()).select_from(Block).where(Block.blocker_id == caller.id)
    )
    assert count == 1


def test_put_block_rejects_blocking_yourself(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)

    response = api_client.put(
        f"{_BASE}/{caller.id}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "CANNOT_BLOCK_SELF"}
    assert _blocked_ids(db_session, caller) == set()


def test_put_block_unknown_user_is_404(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)

    response = api_client.put(
        f"{_BASE}/{uuid.uuid4()}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found."}
    assert _blocked_ids(db_session, caller) == set()


@pytest.mark.parametrize(
    "overrides",
    [{"active": False}, {"verified": False}, {"username": False}],
    ids=["inactive", "unverified", "no_username"],
)
def test_put_block_ineligible_user_is_404(
    api_client: TestClient,
    db_session: Session,
    overrides: dict[str, bool],
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session, **overrides)

    response = api_client.put(
        f"{_BASE}/{target.id}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 404
    assert _blocked_ids(db_session, caller) == set()


def test_put_block_does_not_reveal_that_the_other_user_blocked_the_caller(
    api_client: TestClient,
    db_session: Session,
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    _block(db_session, target, caller)

    response = api_client.put(
        f"{_BASE}/{target.id}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 204
    assert _blocked_ids(db_session, caller) == {target.id}
    assert _blocked_ids(db_session, target) == {caller.id}


def test_put_block_rejects_a_malformed_user_id(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)

    response = api_client.put(
        f"{_BASE}/not-a-uuid/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 422


def test_put_block_requires_authentication(api_client: TestClient) -> None:
    assert api_client.put(f"{_BASE}/{uuid.uuid4()}/block").status_code == 401


# ------------------------------------------------------------------ DELETE


def test_delete_block_removes_only_the_callers_block(
    api_client: TestClient, db_session: Session
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    _block(db_session, caller, target)
    _block(db_session, target, caller)

    response = api_client.delete(
        f"{_BASE}/{target.id}/block", headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 204
    assert _blocked_ids(db_session, caller) == set()
    assert _blocked_ids(db_session, target) == {caller.id}


def test_delete_block_is_idempotent_for_missing_and_unknown_users(
    api_client: TestClient, db_session: Session
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    assert api_client.delete(f"{_BASE}/{target.id}/block", headers=headers).status_code == 204
    assert api_client.delete(f"{_BASE}/{uuid.uuid4()}/block", headers=headers).status_code == 204
    assert api_client.delete(f"{_BASE}/{caller.id}/block", headers=headers).status_code == 204


def test_delete_block_requires_authentication(api_client: TestClient) -> None:
    assert api_client.delete(f"{_BASE}/{uuid.uuid4()}/block").status_code == 401


# ------------------------------------------------------------------ list


def test_list_is_empty_without_blocks(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


def test_list_returns_blocked_users_with_public_fields_only(
    api_client: TestClient, db_session: Session
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    other = _make_user(db_session)
    _block(db_session, caller, target)
    _block(db_session, other, caller)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {"id": str(target.id), "username": target.username, "display_name": "Block Test"}
        ],
        "next_cursor": None,
    }


def test_list_does_not_show_other_users_blocks(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)
    other = _make_user(db_session)
    victim = _make_user(db_session)
    _block(db_session, other, victim)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert response.json()["items"] == []


def test_list_omits_ineligible_blocked_users(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)
    eligible = _make_user(db_session)
    for overrides in ({"active": False}, {"verified": False}, {"username": False}):
        _block(db_session, caller, _make_user(db_session, **overrides))
    _block(db_session, caller, eligible)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert [item["id"] for item in response.json()["items"]] == [str(eligible.id)]


def test_list_orders_newest_block_first(api_client: TestClient, db_session: Session) -> None:
    caller = _make_user(db_session)
    oldest = _make_user(db_session)
    middle = _make_user(db_session)
    newest = _make_user(db_session)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    _block(db_session, caller, middle, base + timedelta(days=1))
    _block(db_session, caller, newest, base + timedelta(days=2))
    _block(db_session, caller, oldest, base)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert [item["id"] for item in response.json()["items"]] == [
        str(newest.id),
        str(middle.id),
        str(oldest.id),
    ]


def test_list_pages_without_duplicates_or_gaps_across_ties(
    api_client: TestClient, db_session: Session
) -> None:
    caller = _make_user(db_session)
    newer_time = datetime(2026, 2, 1, 12, 0, 0, 123456, tzinfo=UTC)
    older_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    newer = [_make_user(db_session) for _ in range(3)]
    older = [_make_user(db_session) for _ in range(2)]
    for user in newer:
        _block(db_session, caller, user, newer_time)
    for user in older:
        _block(db_session, caller, user, older_time)
    expected = [u.id for u in sorted(newer, key=lambda u: u.id)] + [
        u.id for u in sorted(older, key=lambda u: u.id)
    ]
    headers = _auth_headers(db_session, caller)

    collected: list[uuid.UUID] = []
    cursor = None
    for _ in range(10):
        params: dict[str, object] = {"limit": 2}
        if cursor is not None:
            params["cursor"] = cursor
        response = api_client.get(_BLOCKS, params=params, headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert len(body["items"]) <= 2
        collected.extend(uuid.UUID(item["id"]) for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert cursor is None
    assert collected == expected


@pytest.mark.parametrize(
    "cursor",
    ["!!!", "not-a-cursor", "abcd", _raw_cursor([1, 2]), _raw_cursor({"i": "x", "t": "y"})],
)
def test_list_rejects_malformed_cursors(
    api_client: TestClient, db_session: Session, cursor: str
) -> None:
    caller = _make_user(db_session)

    response = api_client.get(
        _BLOCKS, params={"cursor": cursor}, headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_CURSOR"}


@pytest.mark.parametrize("limit", [0, 51, -1])
def test_list_rejects_out_of_range_limits(
    api_client: TestClient, db_session: Session, limit: int
) -> None:
    caller = _make_user(db_session)

    response = api_client.get(
        _BLOCKS, params={"limit": limit}, headers=_auth_headers(db_session, caller)
    )

    assert response.status_code == 422


def test_list_requires_authentication(api_client: TestClient) -> None:
    assert api_client.get(_BLOCKS).status_code == 401


def test_blocks_route_is_not_shadowed_by_user_lookup(
    api_client: TestClient, db_session: Session
) -> None:
    caller = _make_user(db_session)

    response = api_client.get(_BLOCKS, headers=_auth_headers(db_session, caller))

    assert response.status_code == 200
    assert set(response.json()) == {"items", "next_cursor"}


# ------------------------------------------------------------------ cursor helpers


def test_cursor_round_trips() -> None:
    created_at = datetime(2026, 3, 4, 5, 6, 7, 891011, tzinfo=UTC)
    blocked_id = uuid.uuid4()

    decoded = decode_block_cursor(encode_block_cursor(created_at, blocked_id))

    assert decoded == (created_at, blocked_id)


@pytest.mark.parametrize(
    "payload",
    [
        {"i": str(uuid.uuid4()), "t": "2026-01-01T00:00:00"},
        {"i": str(uuid.uuid4()), "t": "2026-01-01T00:00:00Z"},
        {"i": str(uuid.uuid4()), "t": "2026-01-01T03:00:00+03:00"},
        {"i": str(uuid.uuid4()).upper(), "t": "2026-01-01T00:00:00+00:00"},
        {"i": str(uuid.uuid4())},
        {"i": str(uuid.uuid4()), "t": "2026-01-01T00:00:00+00:00", "x": 1},
        {"i": 1, "t": "2026-01-01T00:00:00+00:00"},
    ],
    ids=["naive", "z_suffix", "offset", "uppercase_id", "missing_time", "extra_key", "bad_id"],
)
def test_cursor_decoder_rejects_non_canonical_payloads(payload: dict[str, object]) -> None:
    with pytest.raises(InvalidBlockCursorError):
        decode_block_cursor(_raw_cursor(payload))


# ------------------------------------------------------------------ mutual hiding


def test_blocked_users_are_hidden_from_search_in_both_directions(
    api_client: TestClient, db_session: Session
) -> None:
    blocker = _make_user(db_session)
    blocked = _make_user(db_session)
    bystander = _make_user(db_session)
    _block(db_session, blocker, blocked)

    blocker_headers = _auth_headers(db_session, blocker)
    blocked_headers = _auth_headers(db_session, blocked)
    bystander_headers = _auth_headers(db_session, bystander)

    assert str(blocked.id) not in _search_ids(api_client, blocker_headers, blocked.username)
    assert str(blocker.id) not in _search_ids(api_client, blocked_headers, blocker.username)
    assert str(blocked.id) in _search_ids(api_client, bystander_headers, blocked.username)
    assert str(blocker.id) in _search_ids(api_client, bystander_headers, blocker.username)


def test_blocked_users_return_404_from_lookup_in_both_directions(
    api_client: TestClient, db_session: Session
) -> None:
    blocker = _make_user(db_session)
    blocked = _make_user(db_session)
    bystander = _make_user(db_session)
    _block(db_session, blocker, blocked)

    assert (
        api_client.get(
            f"{_BASE}/{blocked.id}", headers=_auth_headers(db_session, blocker)
        ).status_code
        == 404
    )
    assert (
        api_client.get(
            f"{_BASE}/{blocker.id}", headers=_auth_headers(db_session, blocked)
        ).status_code
        == 404
    )
    assert (
        api_client.get(
            f"{_BASE}/{blocked.id}", headers=_auth_headers(db_session, bystander)
        ).status_code
        == 200
    )


def test_unblocking_restores_visibility(api_client: TestClient, db_session: Session) -> None:
    blocker = _make_user(db_session)
    blocked = _make_user(db_session)
    headers = _auth_headers(db_session, blocker)

    assert api_client.put(f"{_BASE}/{blocked.id}/block", headers=headers).status_code == 204
    assert api_client.get(f"{_BASE}/{blocked.id}", headers=headers).status_code == 404

    assert api_client.delete(f"{_BASE}/{blocked.id}/block", headers=headers).status_code == 204
    assert api_client.get(f"{_BASE}/{blocked.id}", headers=headers).status_code == 200
    assert str(blocked.id) in _search_ids(api_client, headers, blocked.username)


# ------------------------------------------------------------------ database rules


def test_database_rejects_a_self_block(db_session: Session) -> None:
    user = _make_user(db_session)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(Block(blocker_id=user.id, blocked_id=user.id))
            db_session.flush()


def test_deleting_a_user_removes_their_blocks(db_session: Session) -> None:
    first = _make_user(db_session)
    second = _make_user(db_session)
    _block(db_session, first, second)
    _block(db_session, second, first)

    db_session.execute(delete(User).where(User.id == second.id))

    count = db_session.scalar(
        select(func.count()).select_from(Block).where(Block.blocker_id.in_([first.id, second.id]))
    )
    assert count == 0


# ------------------------------------------------------------------ limits and failures

_ROUTE_PREFIX = {"put": "block", "delete": "unblock", "get": "list-blocks"}


def _call(api_client: TestClient, method: str, target_id: uuid.UUID, headers: dict[str, str]):
    if method == "get":
        return api_client.get(_BLOCKS, headers=headers)
    return getattr(api_client, method)(f"{_BASE}/{target_id}/block", headers=headers)


@pytest.mark.parametrize("method", ["put", "delete", "get"])
def test_endpoints_return_429_when_rate_limited(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)
    observed: dict[str, object] = {}

    def deny_request(buckets: list[object]) -> RateLimitResult:
        observed["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=42)

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", deny_request)

    response = _call(api_client, method, target.id, headers)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"
    prefix = _ROUTE_PREFIX[method]
    buckets = observed["buckets"]
    assert isinstance(buckets, list)
    assert [(b.scope, b.kind) for b in buckets] == [
        (f"users:{prefix}:ip", "ip"),
        (f"users:{prefix}:user", "email"),
    ]
    assert _blocked_ids(db_session, caller) == set()


@pytest.mark.parametrize("method", ["put", "delete", "get"])
def test_endpoints_fail_closed_when_rate_limit_database_fails(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    def fail_limiter(_buckets: list[object]) -> RateLimitResult:
        raise SQLAlchemyError("simulated rate-limit database failure")

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", fail_limiter)

    response = _call(api_client, method, target.id, headers)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}


@pytest.mark.parametrize(
    ("method", "function"),
    [("put", "block_user"), ("delete", "unblock_user"), ("get", "list_blocked_users")],
)
def test_endpoints_return_503_on_database_error(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    function: str,
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise SQLAlchemyError("simulated database failure")

    monkeypatch.setattr(f"app.api.v1.endpoints.user_blocks.{function}", fail)

    response = _call(api_client, method, target.id, headers)

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}


def test_put_block_maps_an_integrity_error_to_404(
    api_client: TestClient,
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller = _make_user(db_session)
    target = _make_user(db_session)
    headers = _auth_headers(db_session, caller)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise IntegrityError("INSERT", {}, Exception("target vanished"))

    monkeypatch.setattr("app.api.v1.endpoints.user_blocks.block_user", fail)

    response = api_client.put(f"{_BASE}/{target.id}/block", headers=headers)

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found."}
