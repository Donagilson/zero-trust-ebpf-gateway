"""Authentication helpers for validating Keycloak-issued access tokens."""
"""Authentication helpers for validating Keycloak-issued access tokens."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    """Identity and roles extracted from a successfully validated JWT."""

    subject: str
    username: str | None
    roles: frozenset[str]
    claims: dict[str, Any]


def _settings() -> tuple[str, str, str]:
    issuer = os.getenv("KEYCLOAK_ISSUER", "").rstrip("/")
    audience = os.getenv("KEYCLOAK_AUDIENCE", "")
    jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "")

    if not issuer or not audience:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication is not configured: set KEYCLOAK_ISSUER and KEYCLOAK_AUDIENCE",
        )

    if not jwks_url:
        jwks_url = f"{issuer}/protocol/openid-connect/certs"

    return issuer, audience, jwks_url


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> Any:
    try:
        from jwt import PyJWKClient
    except ImportError as exc:
        raise RuntimeError(
            "JWT validation requires PyJWT with cryptography support "
            "(install the PyJWT[crypto] package)"
        ) from exc

    return PyJWKClient(jwks_url, timeout=5)


def validate_access_token(token: str) -> AuthenticatedUser:
    """Validate a Keycloak RS256 access token and return its trusted identity."""
    issuer, audience, jwks_url = _settings()

    try:
        import jwt
        from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
    except ImportError as exc:
        raise RuntimeError(
            "JWT validation requires PyJWT with cryptography support "
            "(install the PyJWT[crypto] package)"
        ) from exc

    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token).key
    except PyJWKClientConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve Keycloak signing keys",
        ) from exc
    except PyJWKClientError as exc:
        raise _unauthorized("Invalid bearer token") from exc
    except jwt.InvalidTokenError as exc:
        raise _unauthorized("Invalid bearer token") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "sub", "aud"]},
        )
    except jwt.InvalidTokenError as exc:
        raise _unauthorized("Invalid or expired bearer token") from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise _unauthorized("Bearer token has no valid subject")

    roles: set[str] = set()
    raw_roles = claims.get("roles", [])
    if isinstance(raw_roles, list):
        roles.update(role for role in raw_roles if isinstance(role, str))

    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        realm_roles = realm_access.get("roles", [])
        if isinstance(realm_roles, list):
            roles.update(role for role in realm_roles if isinstance(role, str))

    username = claims.get("preferred_username")
    if not isinstance(username, str):
        username = None

    return AuthenticatedUser(
        subject=subject,
        username=username,
        roles=frozenset(roles),
        claims=claims,
    )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser:
    """FastAPI dependency that requires a valid Keycloak bearer token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized("Bearer token required")

    return validate_access_token(credentials.credentials)

