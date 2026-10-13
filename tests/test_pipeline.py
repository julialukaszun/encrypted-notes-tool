import pytest

from crypto.cipher import decrypt, encrypt
from crypto.constants import HEADER_SIZE, MIN_ITERATIONS, MIN_MEMORY_BYTES
from crypto.errors import DecryptionError, FormatError, InvalidParametersError
from crypto.file_format import decode, encode
from crypto.kdf import derive_key, generate_salt

PASSWORD = "correct horse battery staple"
NOTES = b'{"notes": [{"id": 1, "title": "hi", "text": "secret"}]}'


def make_file(password: str = PASSWORD, plaintext: bytes = NOTES) -> bytes:
    salt = generate_salt()
    key = derive_key(password, salt, MIN_MEMORY_BYTES, MIN_ITERATIONS)
    blob = encrypt(key, plaintext)
    return encode(salt=salt,
                  memory_bytes=MIN_MEMORY_BYTES, iterations=MIN_ITERATIONS, blob=blob)


def open_file(file_bytes: bytes, password: str) -> bytes:
    salt, memory_bytes, iterations, blob = decode(file_bytes)
    key = derive_key(password, salt, memory_bytes, iterations)
    return decrypt(key, blob)


def test_full_round_trip():
    assert open_file(make_file(), PASSWORD) == NOTES


def test_wrong_password_fails():
    with pytest.raises(DecryptionError):
        open_file(make_file(), "wrong password")