"""Authentication and authorization primitives (Phase 14).

Passwords are hashed with Argon2id (argon2-cffi); plaintext passwords are never stored.
Sessions are short-lived JWTs signed with HS256. The signing secret must come from the
environment (MALVAX_JWT_SECRET); there is no built-in default for production use.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ACCESS_TOKEN_TTL_MINUTES = 60
JWT_ALGORITHM = "HS256"
_hasher = PasswordHasher()


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


# What each role may do, per docs/architecture.md. Admin includes every Analyst permission.
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"view_reports"}),
    Role.ANALYST: frozenset({"view_reports", "submit_samples", "start_analysis"}),
    Role.ADMIN: frozenset({"view_reports", "submit_samples", "start_analysis", "manage_users",
                           "manage_config"}),
}


class InvalidCredentialsError(ValueError):
    """Raised by authenticate() when the username or password does not match."""


class InvalidTokenError(ValueError):
    """Raised when a bearer token is missing, expired, or signed with the wrong secret."""


@dataclass(frozen=True, slots=True)
class TokenPayload:
    user_id: str
    username: str
    role: Role


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def create_access_token(user_id: str, username: str, role: Role, secret: str,
                        now: datetime | None = None) -> str:
    issued = now or datetime.now(UTC)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role.value,
        "iat": issued,
        "exp": issued + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, secret: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
    try:
        role = Role(payload["role"])
    except (KeyError, ValueError) as exc:
        raise InvalidTokenError("token is missing a valid role") from exc
    return TokenPayload(user_id=payload["sub"], username=payload["username"], role=role)


def role_allows(role: Role, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS[role]
