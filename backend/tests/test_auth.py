from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app import auth


class FakeSigningKey:
    def __init__(self, key):
        self.key = key


class FakeJwksClient:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return FakeSigningKey(self.key)


@pytest.fixture
def token_keys(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    monkeypatch.setattr(
        auth,
        "_settings",
        lambda: (
            "https://keycloak.example/realms/zero-trust",
            "gateway-api",
            "https://keycloak.example/certs",
        ),
    )
    monkeypatch.setattr(
        auth,
        "_jwks_client",
        lambda _url: FakeJwksClient(public_key),
    )
    return private_key


def make_token(private_key, **overrides):
    claims = {
        "iss": "https://keycloak.example/realms/zero-trust",
        "aud": "gateway-api",
        "sub": "subject-1",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "realm_access": {"roles": ["gateway-user"]},
        "wg_client_ipv4": "10.77.0.2",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256")


def test_valid_keycloak_token_extracts_identity_and_roles(token_keys):
    user = auth.validate_access_token(make_token(token_keys))

    assert user.subject == "subject-1"
    assert user.roles == frozenset({"gateway-user"})
    assert user.claims["wg_client_ipv4"] == "10.77.0.2"


def test_invalid_issuer_is_rejected(token_keys):
    token = make_token(token_keys, iss="https://attacker.example/")

    with pytest.raises(HTTPException) as error:
        auth.validate_access_token(token)

    assert error.value.status_code == 401
