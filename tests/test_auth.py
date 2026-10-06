import time

import jwt
import pytest

from malvax.auth import (
    InvalidTokenError,
    Role,
    create_access_token,
    decode_access_token,
    hash_password,
    needs_rehash,
    role_allows,
    verify_password,
)

SECRET = "test-secret-not-for-production-0123456789"


def test_password_hash_is_not_plaintext_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong password", hashed)


def test_short_password_is_rejected() -> None:
    with pytest.raises(ValueError, match="8 characters"):
        hash_password("short")


def test_hash_is_salted_differently_each_time() -> None:
    a = hash_password("same password 123")
    b = hash_password("same password 123")
    assert a != b
    assert verify_password("same password 123", a)
    assert verify_password("same password 123", b)


def test_needs_rehash_is_false_for_current_params() -> None:
    assert needs_rehash(hash_password("another password 123")) is False


def test_token_round_trip() -> None:
    token = create_access_token("user-1", "alice", Role.ANALYST, SECRET)
    payload = decode_access_token(token, SECRET)
    assert payload.user_id == "user-1"
    assert payload.username == "alice"
    assert payload.role is Role.ANALYST


def test_token_rejected_with_wrong_secret() -> None:
    token = create_access_token("user-1", "alice", Role.VIEWER, SECRET)
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, "a-different-secret-0123456789-abcdef")


def test_expired_token_is_rejected() -> None:
    import datetime as dt

    token = create_access_token(
        "user-1", "alice", Role.VIEWER, SECRET,
        now=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2),
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, SECRET)


def test_token_with_unknown_role_is_rejected() -> None:
    bad = jwt.encode(
        {"sub": "u", "username": "x", "role": "root", "iat": time.time(), "exp": time.time() + 60},
        SECRET, algorithm="HS256",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(bad, SECRET)


@pytest.mark.parametrize(
    ("role", "permission", "expected"),
    [
        (Role.VIEWER, "view_reports", True),
        (Role.VIEWER, "submit_samples", False),
        (Role.ANALYST, "submit_samples", True),
        (Role.ANALYST, "manage_users", False),
        (Role.ADMIN, "manage_users", True),
        (Role.ADMIN, "submit_samples", True),  # admin includes analyst permissions
    ],
)
def test_role_permissions(role: Role, permission: str, expected: bool) -> None:
    assert role_allows(role, permission) is expected
