"""
test_app.py

Test suite for the JWKS server (app.py / keys.py).

Covers:
  - JWKS endpoint returns only unexpired keys, correctly formatted
  - /auth issues a valid JWT whose kid appears in JWKS
  - /auth?expired issues an expired JWT signed with a key NOT in JWKS
  - Full signature verification round-trip using only JWKS data
  - Disallowed HTTP methods return 405
"""

import base64
import os
import sys

import jwt
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app  # noqa: E402


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as test_client:
        yield test_client


def b64url_to_int(data: str) -> int:
    padded = data + "=" * (-len(data) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), byteorder="big")


def test_jwks_returns_only_valid_keys(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    body = response.get_json()
    assert "keys" in body
    # only the non-expired key should be published
    assert len(body["keys"]) == 1

    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_auth_issues_valid_jwt(client):
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)
    assert "kid" in header

    jwks_body = client.get("/.well-known/jwks.json").get_json()
    kids = [k["kid"] for k in jwks_body["keys"]]
    assert header["kid"] in kids

    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > decoded["iat"]


def test_auth_expired_issues_expired_jwt(client):
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.get_json()["token"]
    header = jwt.get_unverified_header(token)

    jwks_body = client.get("/.well-known/jwks.json").get_json()
    kids = [k["kid"] for k in jwks_body["keys"]]
    assert header["kid"] not in kids  # expired key must not be published

    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] < decoded["iat"]


def test_jwt_signature_verifies_against_jwks_public_key(client):
    """Full round-trip: rebuild the public key from JWKS and verify the JWT."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    token = client.post("/auth").get_json()["token"]
    header = jwt.get_unverified_header(token)

    jwks_body = client.get("/.well-known/jwks.json").get_json()
    matching = next(k for k in jwks_body["keys"] if k["kid"] == header["kid"])

    n = b64url_to_int(matching["n"])
    e = b64url_to_int(matching["e"])
    public_key = RSAPublicNumbers(e, n).public_key()

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"


def test_auth_get_not_allowed(client):
    response = client.get("/auth")
    assert response.status_code == 405


def test_jwks_post_not_allowed(client):
    response = client.post("/.well-known/jwks.json")
    assert response.status_code == 405
