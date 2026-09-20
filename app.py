"""
app.py

Name: Ananiya Getachew
EUID: aag0447

A simple JWKS server built with Flask.

Routes:
  GET  /.well-known/jwks.json  -> list of public keys that haven't expired
  POST /auth                   -> hands back a signed JWT (no real login
                                   check here, per assignment instructions)
                                   add ?expired to get a token signed with
                                   the already-expired key instead

Run with:  python app.py
Server listens on port 8080.
"""

import base64
import time

import jwt
from flask import Flask, jsonify, request

import keys

app = Flask(__name__)


def int_to_base64url(num):
    """Turn an integer into the base64url string format a JWK needs."""
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
    b64 = base64.urlsafe_b64encode(num_bytes)
    return b64.rstrip(b"=").decode("ascii")


def build_jwk(key_dict):
    """Build one JWK entry (the public part only) from a key dict."""
    numbers = key_dict["public"].public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key_dict["kid"],
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    good_keys = []
    for key_dict in keys.key_list:
        if not keys.is_expired(key_dict):
            good_keys.append(build_jwk(key_dict))
    return jsonify({"keys": good_keys})


@app.route("/auth", methods=["POST"])
def auth():
    # this is just mock authentication, we don't actually check anything
    if "expired" in request.args:
        key_dict = keys.find_key(keys.expired_kid)
    else:
        key_dict = keys.find_key(keys.valid_kid)

    now = int(time.time())
    if "expired" in request.args:
        exp_time = now - 3600
    else:
        exp_time = now + 3600

    payload = {"sub": "fake-user", "iat": now, "exp": exp_time}

    token = jwt.encode(
        payload,
        keys.get_private_pem(key_dict),
        algorithm="RS256",
        headers={"kid": key_dict["kid"]},
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
