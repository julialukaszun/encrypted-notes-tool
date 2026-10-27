"""End-to-end tests: derive_key + encrypt + encode, then decode + derive_key + decrypt."""
import pytest

from crypto.cipher import decrypt, encrypt
from crypto.constants import HEADER_SIZE, MIN_ITERATIONS, MIN_MEMORY_BYTES
from crypto.errors import DecryptionError, FormatError, InvalidParametersError
from crypto.file_format import decode, encode
from crypto.kdf import derive_key, generate_salt

PASSWORD = "correct horse battery staple"
NOTES = b'{"notes": [{"id": 1, "title": "hi", "text": "secret"}]}'

# Byte positions from the layout table
MAGIC_POS = 0
VERSION_POS = 6
KDF_ID_POS = 7
PARAMS_START, PARAMS_END = 8, 16  # memory (8-11) and iterations (12-15)
SALT_START, SALT_END = 16, 32


def make_file(password: str = PASSWORD, plaintext: bytes = NOTES) -> bytes:
    salt = generate_salt()
    key = derive_key(password, salt, MIN_MEMORY_BYTES, MIN_ITERATIONS)
    blob = encrypt(key, plaintext)
    return encode(
        salt=salt,
        memory_bytes=MIN_MEMORY_BYTES,
        iterations=MIN_ITERATIONS,
        blob=blob,
    )


def open_file(file_bytes: bytes, password: str) -> bytes:
    salt, memory_bytes, iterations, blob = decode(file_bytes)
    key = derive_key(password, salt, memory_bytes, iterations)
    return decrypt(key, blob)


def flip_byte(data: bytes, position: int) -> bytes:
    """Return a copy of data with one byte changed."""
    tampered = bytearray(data)
    tampered[position] ^= 0x01
    return bytes(tampered)


@pytest.fixture(scope="module")
def valid_file() -> bytes:
    # Built once, because Argon2 makes each make_file call slow.
    # bytes are immutable, so tests can't change it by accident.
    return make_file()


# ---------- happy path ----------

def test_full_round_trip(valid_file):
    assert open_file(valid_file, PASSWORD) == NOTES


def test_empty_notes_round_trip():
    assert open_file(make_file(plaintext=b""), PASSWORD) == b""


def test_unicode_password_normalization():
    composed = "caf\u00e9"
    decomposed = "cafe\u0301"
    assert composed != decomposed
    assert open_file(make_file(password=composed), decomposed) == NOTES


# ---------- privacy and freshness ----------

def test_plaintext_not_visible_in_file(valid_file):
    assert NOTES not in valid_file
    assert b"secret" not in valid_file


def test_two_files_from_same_input_differ():
    assert make_file() != make_file()


# ---------- wrong password ----------

def test_wrong_password_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(valid_file, "wrong password")


# ---------- tampering: body ----------

def test_tampered_body_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(flip_byte(valid_file, HEADER_SIZE + 30), PASSWORD)


def test_tampered_nonce_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(flip_byte(valid_file, HEADER_SIZE), PASSWORD)


def test_tampered_tag_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(flip_byte(valid_file, len(valid_file) - 1), PASSWORD)


def test_missing_last_byte_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(valid_file[:-1], PASSWORD)


def test_appended_byte_fails(valid_file):
    with pytest.raises(DecryptionError):
        open_file(valid_file + b"\x00", PASSWORD)


# ---------- tampering: header ----------

@pytest.mark.parametrize("position", range(SALT_START, SALT_END))
def test_tampered_salt_fails(valid_file, position):
    # A changed salt derives a different key, so decryption fails.
    with pytest.raises(DecryptionError):
        open_file(flip_byte(valid_file, position), PASSWORD)


@pytest.mark.parametrize("position", range(PARAMS_START, PARAMS_END))
def test_tampered_parameters_fail(valid_file, position):
    # Small changes give a valid but different setting (wrong key -> DecryptionError).
    # Large changes fall outside the allowed range (rejected by derive_key).
    with pytest.raises((DecryptionError, InvalidParametersError)):
        open_file(flip_byte(valid_file, position), PASSWORD)


@pytest.mark.parametrize("position", [MAGIC_POS, MAGIC_POS + 5, VERSION_POS, KDF_ID_POS])
def test_tampered_format_fields_rejected(valid_file, position):
    with pytest.raises(FormatError):
        open_file(flip_byte(valid_file, position), PASSWORD)


# ---------- truncation ----------

def test_header_only_file_rejected(valid_file):
    with pytest.raises(FormatError):
        open_file(valid_file[:HEADER_SIZE], PASSWORD)


def test_empty_file_rejected():
    with pytest.raises(FormatError):
        open_file(b"", PASSWORD)


def test_random_garbage_rejected():
    import os
    with pytest.raises(FormatError):
        open_file(os.urandom(200), PASSWORD)