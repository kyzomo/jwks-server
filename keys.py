"""
keys.py

Generates the RSA keys used by the JWKS server.

Instead of classes, keys are just stored as dictionaries in a global
list. Each key dict has:
    kid      - unique id string
    private  - RSA private key object
    public   - RSA public key object
    expiry   - unix timestamp when the key expires

We only ever have two keys: one valid, one already expired (so the
/auth?expired route has something to sign with).
"""

import time
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# global list holding our two keys
key_list = []


def make_key(expiry_offset_seconds):
    """Generate one RSA key pair and store it in key_list. Returns the kid."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    key_dict = {
        "kid": str(uuid.uuid4()),
        "private": private_key,
        "public": private_key.public_key(),
        "expiry": int(time.time()) + expiry_offset_seconds,
    }
    key_list.append(key_dict)
    return key_dict["kid"]


def is_expired(key_dict):
    return time.time() > key_dict["expiry"]


def get_private_pem(key_dict):
    """Return the private key as PEM bytes, the format PyJWT wants."""
    return key_dict["private"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def find_key(kid):
    for key_dict in key_list:
        if key_dict["kid"] == kid:
            return key_dict
    return None


# set up the two keys as soon as this module is imported
valid_kid = make_key(3600)      # expires in 1 hour
expired_kid = make_key(-3600)   # already expired 1 hour ago
