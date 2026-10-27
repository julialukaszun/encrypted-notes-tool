# kdf.py
import nacl.utils
import unicodedata
from nacl.pwhash import argon2id
from crypto.constants import (MIN_MEMORY_BYTES, MAX_MEMORY_BYTES,
                              MIN_ITERATIONS, MAX_ITERATIONS, SALT_LENGTH, KEY_LENGTH)
from crypto.errors import InvalidParametersError

def generate_salt() -> bytes:
    return nacl.utils.random(SALT_LENGTH)

def derive_key(password: str, salt: bytes, memory_bytes: int, iterations: int) -> bytes:
    if len(salt) != SALT_LENGTH:
        raise InvalidParametersError()
    if not MIN_MEMORY_BYTES <= memory_bytes <= MAX_MEMORY_BYTES:
        raise InvalidParametersError("memory cost out of range")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise InvalidParametersError("iteration count out of range")
    if memory_bytes % 1024 != 0:
        raise InvalidParametersError("memory cost must be multiple of 1024") # libsodium rounds memory down to KiB

    normalized = unicodedata.normalize("NFKC", password)
    password_bytes = normalized.encode("utf-8")

    return argon2id.kdf(
        KEY_LENGTH,
        password_bytes,
        salt,
        opslimit=iterations,
        memlimit=memory_bytes,
    )


