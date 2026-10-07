"""Negative controls for the test-only authentication boundary."""

import time

import jwt
import pytest

from tests.canary_services import OTHER_USER, USER, verified_user

KEY = "disposable-local-canary-signing-key" * 2


def token(**overrides):
    return jwt.encode(
        {
            "sub": USER,
            "exp": int(time.time()) + 60,
            "aud": "authenticated",
            "iss": "local-canary",
            **overrides,
        },
        KEY,
        algorithm="HS256",
    )


def test_fixture_verifies_signature_expiry_and_server_owned_identity():
    assert verified_user(token(), KEY)["id"] == USER
    other = verified_user(token(sub=OTHER_USER), KEY)
    assert other["app_metadata"] == {}
    assert other["user_metadata"] == {"role": "admin"}
    with pytest.raises(jwt.PyJWTError):
        verified_user(token(), "wrong-key" * 8)
    for overrides in ({"exp": 1}, {"aud": "wrong"}, {"iss": "wrong"}):
        with pytest.raises(jwt.PyJWTError):
            verified_user(token(**overrides), KEY)
    with pytest.raises(ValueError):
        verified_user(token(sub="unknown"), KEY)
