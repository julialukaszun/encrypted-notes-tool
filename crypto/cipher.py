# cipher.py

import nacl.utils
import nacl.secret
import unicodedata
from nacl.pwhash import argon2id
from crypto.constants import (MIN_MEMORY_BYTES, MAX_MEMORY_BYTES,
                              MIN_ITERATIONS, MAX_ITERATIONS, SALT_LENGTH, KEY_LENGTH)
from crypto.errors import InvalidParametersError, DecryptionError


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != KEY_LENGTH:
        raise InvalidParametersError("invalid key length")
    box = nacl.secret.SecretBox(key)
    return bytes(box.encrypt(plaintext))

def decrypt(key, blob) -> bytes:
    if len(key) != KEY_LENGTH:
        raise InvalidParametersError()

    box = nacl.secret.SecretBox(key)

    try:
        return box.decrypt(blob)
    except nacl.exceptions.CryptoError:
        raise DecryptionError("wrong password or corrupted data") from None

