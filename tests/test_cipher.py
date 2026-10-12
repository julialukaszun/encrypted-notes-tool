import os
import pytest

from crypto.cipher import decrypt, encrypt
from crypto.constants import KEY_LENGTH
from crypto.errors import DecryptionError, InvalidParametersError

NONCE_SIZE = 24
TAG_SIZE = 16
OVERHEAD = NONCE_SIZE + TAG_SIZE


def new_key() -> bytes:
    return os.urandom(KEY_LENGTH)


# ---------- round trips ----------

def test_round_trip():
    key = new_key()
    assert decrypt(key, encrypt(key, b"hello")) == b"hello"


def test_round_trip_empty_plaintext():
    key = new_key()
    assert decrypt(key, encrypt(key, b"")) == b""


def test_round_trip_large_plaintext():
    key = new_key()
    data = os.urandom(1_000_000)
    assert decrypt(key, encrypt(key, data)) == data


# ---------- output properties ----------

def test_output_returns_plain_bytes():
    assert type(encrypt(new_key(), b"hello")) is bytes


def test_output_length_is_plaintext_plus_overhead():
    key = new_key()
    assert len(encrypt(key, b"hello")) == len(b"hello") + OVERHEAD


def test_encrypting_twice_gives_different_output():
    key = new_key()
    assert encrypt(key, b"hello") != encrypt(key, b"hello")


def test_nonces_are_unique_across_many_encryptions():
    key = new_key()
    nonces = {encrypt(key, b"x")[:NONCE_SIZE] for _ in range(1000)}
    assert len(nonces) == 1000


def test_plaintext_not_visible_in_ciphertext():
    key = new_key()
    secret = b"super secret note text"
    assert secret not in encrypt(key, secret)


# ---------- failures: wrong key ----------

def test_wrong_key_fails():
    blob = encrypt(new_key(), b"hello")
    with pytest.raises(DecryptionError):
        decrypt(new_key(), blob)


# ---------- failures: tampering ----------

@pytest.mark.parametrize("position", [0, NONCE_SIZE - 1, NONCE_SIZE, -1])
def test_flipped_byte_fails(position):
    # Covers the nonce, the start of the ciphertext, and the tag.
    key = new_key()
    tampered = bytearray(encrypt(key, b"hello world"))
    tampered[position] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(key, bytes(tampered))


def test_appended_byte_fails():
    key = new_key()
    with pytest.raises(DecryptionError):
        decrypt(key, encrypt(key, b"hello") + b"\x00")


def test_swapped_ciphertexts_do_not_mix():
    key = new_key()
    a = encrypt(key, b"note A")
    b = encrypt(key, b"note B")
    assert decrypt(key, a) == b"note A"
    assert decrypt(key, b) == b"note B"


# ---------- failures: truncated or empty input ----------

@pytest.mark.parametrize("length", [0, 1, NONCE_SIZE - 1, NONCE_SIZE, OVERHEAD - 1])
def test_truncated_blob_fails(length):
    key = new_key()
    blob = encrypt(key, b"hello")
    with pytest.raises(DecryptionError):
        decrypt(key, blob[:length])


def test_blob_missing_last_byte_fails():
    key = new_key()
    blob = encrypt(key, b"hello")
    with pytest.raises(DecryptionError):
        decrypt(key, blob[:-1])


# ---------- failures: bad key length ----------

@pytest.mark.parametrize("length", [0, KEY_LENGTH - 1, KEY_LENGTH + 1])
def test_encrypt_rejects_bad_key_length(length):
    with pytest.raises(InvalidParametersError):
        encrypt(b"\x00" * length, b"hello")


@pytest.mark.parametrize("length", [0, KEY_LENGTH - 1, KEY_LENGTH + 1])
def test_decrypt_rejects_bad_key_length(length):
    blob = encrypt(new_key(), b"hello")
    with pytest.raises(InvalidParametersError):
        decrypt(b"\x00" * length, blob)


# ---------- error message hygiene ----------

def test_error_message_does_not_leak_key_or_plaintext():
    key = new_key()
    blob = encrypt(key, b"top secret")
    with pytest.raises(DecryptionError) as exc:
        decrypt(new_key(), blob)
    message = str(exc.value).encode()
    assert key.hex().encode() not in message
    assert b"top secret" not in message
