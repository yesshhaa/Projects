"""
crypto_layer.py
Optional stretch-goal layer: encrypt the message BEFORE hiding it, so an
attacker who suspects/detects steganography (e.g. via chi-square analysis)
still can't read the payload without the password.

Uses Fernet (AES-128-CBC + HMAC, from the `cryptography` package) with a
key derived from a user password via PBKDF2-HMAC-SHA256. This mirrors how
you'd combine steganography with cryptography in a real defense-in-depth
design -- a good interview talking point.
"""

import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
PBKDF2_ITERATIONS = 480_000  # OWASP-recommended minimum as of 2023+


class CryptoError(Exception):
    pass


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt(message: bytes, password: str) -> bytes:
    """Returns salt + Fernet token, ready to be hidden in the image."""
    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(message)
    return salt + token


def decrypt(payload: bytes, password: str) -> bytes:
    """Reverses encrypt(). Raises CryptoError on wrong password / tampering."""
    if len(payload) < SALT_SIZE:
        raise CryptoError("Payload too short to contain a valid salt.")
    salt, token = payload[:SALT_SIZE], payload[SALT_SIZE:]
    key = _derive_key(password, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        raise CryptoError("Wrong password, or the hidden data was tampered with / corrupted.")
