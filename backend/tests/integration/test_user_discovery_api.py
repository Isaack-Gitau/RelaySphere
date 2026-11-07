import base64
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db_session
from app.main import app
from app.models.refresh_session import RefreshSession
from app.models.user import User
from app.models.username_claim import UsernameClaim
from app.security import tokens
from app.services.rate_limiting import RateLimitResult
from app.services.refresh_sessions import create_refresh_session

SEARCH = "/api/v1/users"
MODULE = "app.api.v1.endpoints.user_discovery"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


@pytest.fixture
def api_client(db_session: Session) -> Generator[TestClient]:
    """Use the isolated integration-test session for HTTP requests."""

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


def new_prefix() -> str:
    return "zq" + uuid.uuid4().hex[:8]


def make_user(
    db: Session,
    *,
    username: str,
    display_name: str = "Person",
    active: bool = True,
    verified: bool = True,
    with_username: bool = True,
) -> User:
    user = User(
        email=f"{uuid.uuid4().hex}@example.com",
        display_name=display_name,
        password_hash=None,
        is_active=active,
        email_verified_at=datetime.now(UTC) if verified else None,
    )
    db.add(user)
    db.flush()
    if with_username:
        db.add(UsernameClaim(username=username, claim_type="permanent", user_id=user.id))
        db.flush()
    return user


def auth_headers(db: Session, user: User) -> dict[str, str]:
    create_refresh_session(db, user.id)
    record = db.scalar(select(RefreshSession).where(RefreshSession.user_id == user.id))
    assert record is not None
    record.last_used_at = datetime.now(UTC)
    db.flush()
    token = tokens.create_access_token(subject=str(user.id), session_id=str(record.id))
    return {"Authorization": f"Bearer {token}"}


def caller_setup(db: Session, username: str | None = None) -> tuple[User, dict[str, str]]:
    caller = make_user(
        db,
        username=username or "me" + uuid.uuid4().hex[:10],
        display_name="Caller",
    )
    return caller, auth_headers(db, caller)


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def non_canonical(value: str) -> str:
    return value[:-1] + ALPHABET[ALPHABET.index(value[-1]) ^ 1]


VALID_CURSOR = b64(b'{"r":0,"u":"abc"}')

BAD_CURSORS = [
    "",
    "!!!",
    "a",
    b64(b"not json"),
    b64(b'[0,"abc"]'),
    b64(b'{"r":0}'),
    b64(b'{"r":0,"u":"abc","x":1}'),
    b64(b'{"r":2,"u":"abc"}'),
    b64(b'{"r":"0","u":"abc"}'),
    b64(b'{"r":true,"u":"abc"}'),
    b64(b'{"r":0,"u":"Abc"}'),
    b64(b'{"r":0,"u":"a__b"}'),
    b64(b'{"r":0,"u":null}'),
    b64(b"\xff\xfe"),
    non_canonical(VALID_CURSOR),
]


def usernames(response) -> list[str]:
    return [item["username"] for item in response.json()["items"]]


def test_search_by_username_prefix_returns_only_public_fields(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    target = make_user(db_session, username=f"{p}_alpha", display_name="Alpha Person")

    response = api_client.get(SEARCH, params={"q": p}, headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "items": [{"id": str(target.id), "username": f"{p}_alpha", "display_name": "Alpha Person"}],
        "next_cursor": None,
    }


def test_search_is_case_insensitive_for_username_and_display_name(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    make_user(db_session, username=f"{p}_a", display_name="Plain")
    make_user(db_session, username="aa" + uuid.uuid4().hex[:10], display_name=f"{p} Zed")

    by_username = api_client.get(SEARCH, params={"q": p.upper()}, headers=headers)
    by_display = api_client.get(SEARCH, params={"q": f"  {p} ZE "}, headers=headers)

    assert len(by_username.json()["items"]) == 2
    assert len(by_display.json()["items"]) == 1


@pytest.mark.parametrize("char", ["%", "_", "!"])
def test_wildcard_characters_match_nothing_extra(api_client, db_session, char) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    make_user(db_session, username=f"{p}abc")

    response = api_client.get(SEARCH, params={"q": p + char}, headers=headers)

    assert response.status_code == 200
    assert response.json()["items"] == []


def test_underscore_in_query_is_literal_not_a_wildcard(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    make_user(db_session, username=f"{p}abc")
    make_user(db_session, username=f"{p}ab_x")

    response = api_client.get(SEARCH, params={"q": f"{p}ab_"}, headers=headers)

    assert usernames(response) == [f"{p}ab_x"]


def test_username_matches_rank_before_display_name_matches(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    display_only = "aa" + uuid.uuid4().hex[:12]
    make_user(db_session, username=display_only, display_name=f"{p} Bee")
    make_user(db_session, username=f"{p}_a", display_name="Zzz One")

    response = api_client.get(SEARCH, params={"q": p}, headers=headers)

    assert usernames(response) == [f"{p}_a", display_only]


def test_user_matching_both_fields_appears_once(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    make_user(db_session, username=f"{p}_x", display_name=f"{p} X")

    response = api_client.get(SEARCH, params={"q": p}, headers=headers)

    assert usernames(response) == [f"{p}_x"]


def test_cursor_paging_walks_across_the_rank_boundary(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    h = uuid.uuid4().hex[:12]
    make_user(db_session, username=f"{p}_r0b")
    make_user(db_session, username=f"{p}_r0a")
    make_user(db_session, username=f"ab{h}", display_name=f"{p} two")
    make_user(db_session, username=f"aa{h}", display_name=f"{p} one")

    collected: list[str] = []
    cursor = None
    pages = 0
    while pages < 10:
        params = {"q": p, "limit": 1}
        if cursor:
            params["cursor"] = cursor
        body = api_client.get(SEARCH, params=params, headers=headers).json()
        collected += [item["username"] for item in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert collected == [f"{p}_r0a", f"{p}_r0b", f"aa{h}", f"ab{h}"]
    assert pages == 4


def test_default_page_size_is_twenty(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    for i in range(21):
        make_user(db_session, username=f"{p}_u{i:02d}")

    first = api_client.get(SEARCH, params={"q": p}, headers=headers).json()
    assert len(first["items"]) == 20
    assert first["next_cursor"] is not None

    second = api_client.get(
        SEARCH, params={"q": p, "cursor": first["next_cursor"]}, headers=headers
    ).json()
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None


@pytest.mark.parametrize("cursor", BAD_CURSORS)
def test_tampered_cursors_are_rejected(api_client, db_session, cursor) -> None:
    _, headers = caller_setup(db_session)

    response = api_client.get(SEARCH, params={"q": "zqnone", "cursor": cursor}, headers=headers)

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_CURSOR"}


def test_well_formed_cursor_is_accepted(api_client, db_session) -> None:
    _, headers = caller_setup(db_session)

    response = api_client.get(
        SEARCH, params={"q": "zqnone", "cursor": VALID_CURSOR}, headers=headers
    )

    assert response.status_code == 200


def test_ineligible_users_and_the_caller_are_hidden(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session, username=f"{p}_self")
    ok = make_user(db_session, username=f"{p}_ok")
    make_user(db_session, username=f"{p}_unv", verified=False)
    make_user(db_session, username=f"{p}_off", active=False)
    make_user(db_session, username="unused", display_name=f"{p} nameless", with_username=False)

    response = api_client.get(SEARCH, params={"q": p}, headers=headers)

    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == [str(ok.id)]


@pytest.mark.parametrize("query", [" ", "a", "a" * 81, "ab\x07", "ab\x00cd", "%"])
def test_invalid_queries_are_rejected_before_the_limiter(
    api_client, db_session, monkeypatch, query
) -> None:
    _, headers = caller_setup(db_session)

    def limiter_must_not_run(_buckets):
        raise AssertionError("limiter must not run")

    monkeypatch.setattr(
        "app.api.v1.endpoints.auth.consume_rate_limit_buckets", limiter_must_not_run
    )

    response = api_client.get(SEARCH, params={"q": query}, headers=headers)

    assert response.status_code == 422
    assert response.json() == {"detail": "INVALID_QUERY"}


def test_missing_query_is_rejected(api_client, db_session) -> None:
    _, headers = caller_setup(db_session)

    assert api_client.get(SEARCH, headers=headers).status_code == 422


@pytest.mark.parametrize("limit", [0, 51])
def test_limit_outside_range_is_rejected(api_client, db_session, limit) -> None:
    _, headers = caller_setup(db_session)

    response = api_client.get(SEARCH, params={"q": "zqnone", "limit": limit}, headers=headers)

    assert response.status_code == 422


def test_authentication_is_checked_before_query_validation(api_client) -> None:
    response = api_client.get(SEARCH, params={"limit": 0})

    assert response.status_code == 401


def test_search_requires_authentication(api_client) -> None:
    assert api_client.get(SEARCH, params={"q": "zqnone"}).status_code == 401


def test_lookup_requires_authentication(api_client) -> None:
    assert api_client.get(f"{SEARCH}/{uuid.uuid4()}").status_code == 401


def test_lookup_returns_public_fields_for_an_eligible_user(api_client, db_session) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    target = make_user(db_session, username=f"{p}_t", display_name="Target")

    response = api_client.get(f"{SEARCH}/{target.id}", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "id": str(target.id),
        "username": f"{p}_t",
        "display_name": "Target",
    }


def test_lookup_of_own_id_returns_the_same_fields(api_client, db_session) -> None:
    caller, headers = caller_setup(db_session)

    response = api_client.get(f"{SEARCH}/{caller.id}", headers=headers)

    assert response.status_code == 200
    assert set(response.json()) == {"id", "username", "display_name"}


@pytest.mark.parametrize("kind", ["unverified", "inactive", "no_username", "unknown"])
def test_lookup_hides_ineligible_and_unknown_users_identically(
    api_client, db_session, kind
) -> None:
    _, headers = caller_setup(db_session)
    if kind == "unknown":
        target_id = uuid.uuid4()
    else:
        target_id = make_user(
            db_session,
            username=f"{new_prefix()}_t",
            active=kind != "inactive",
            verified=kind != "unverified",
            with_username=kind != "no_username",
        ).id

    response = api_client.get(f"{SEARCH}/{target_id}", headers=headers)

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found."}


def test_lookup_rejects_a_malformed_id(api_client, db_session) -> None:
    _, headers = caller_setup(db_session)

    assert api_client.get(f"{SEARCH}/not-a-uuid", headers=headers).status_code == 422


def test_users_me_is_not_shadowed_by_the_lookup_route(api_client, db_session) -> None:
    caller, headers = caller_setup(db_session)

    response = api_client.get(f"{SEARCH}/me", headers=headers)

    assert response.status_code == 200
    assert response.json()["id"] == str(caller.id)


@pytest.mark.parametrize(
    ("kind", "bucket"),
    [("SEARCH", "USER"), ("SEARCH", "IP"), ("LOOKUP", "USER"), ("LOOKUP", "IP")],
)
def test_each_rate_limit_bucket_trips_on_its_own(
    api_client, db_session, monkeypatch, kind, bucket
) -> None:
    p = new_prefix()
    _, headers = caller_setup(db_session)
    target = make_user(db_session, username=f"{p}_t")
    monkeypatch.setattr(f"{MODULE}.{kind}_{bucket}_LIMIT", 2)
    if kind == "SEARCH":
        path, params = SEARCH, {"q": p}
    else:
        path, params = f"{SEARCH}/{target.id}", {}

    statuses = [api_client.get(path, params=params, headers=headers).status_code for _ in range(3)]

    assert statuses == [200, 200, 429]


@pytest.mark.parametrize(
    ("kind", "prefix", "user_limit", "ip_limit"),
    [("SEARCH", "search", 120, 300), ("LOOKUP", "get", 60, 120)],
)
def test_rate_limit_buckets_use_the_agreed_scopes_and_limits(
    api_client, db_session, monkeypatch, kind, prefix, user_limit, ip_limit
) -> None:
    p = new_prefix()
    caller, headers = caller_setup(db_session)
    target = make_user(db_session, username=f"{p}_t")
    seen: dict[str, object] = {}

    def deny(buckets):
        seen["buckets"] = buckets
        return RateLimitResult(allowed=False, retry_after_seconds=1)

    monkeypatch.setattr("app.api.v1.endpoints.auth.consume_rate_limit_buckets", deny)
    path = SEARCH if kind == "SEARCH" else f"{SEARCH}/{target.id}"
    params = {"q": p} if kind == "SEARCH" else {}

    response = api_client.get(path, params=params, headers=headers)

    assert response.status_code == 429
    assert sorted(
        (b.scope, b.kind, b.limit, b.window_seconds, b.identifier) for b in seen["buckets"]
    ) == sorted(
        [
            (f"users:{prefix}:ip", "ip", ip_limit, 900, "testclient"),
            (f"users:{prefix}:user", "email", user_limit, 900, caller.email.casefold()),
        ]
    )
