import pytest

from crypto.constants import (
    HEADER_SIZE, MAGIC_BYTES, FORMAT_VERSION, KDF_ID,
    SALT_LENGTH, MIN_MEMORY_BYTES, MIN_ITERATIONS,
)
from crypto.errors import InvalidParametersError
from crypto.file_format import encode   # adjust to where your file lives
from crypto.kdf import generate_salt

FAST = dict(memory_bytes=MIN_MEMORY_BYTES, iterations=MIN_ITERATIONS)
BLOB = b"\x00" * 50   # stand-in for encrypted data; encode doesn't care what's inside


def test_output_length_is_header_plus_blob():
    out = encode(salt=generate_salt(), blob=BLOB, **FAST)
    assert len(out) == HEADER_SIZE + len(BLOB)

def test_header_starts_with_magic():
    out = encode(salt=generate_salt(), blob=BLOB, **FAST)
    assert out[0:6] == MAGIC_BYTES


def test_version_and_kdf_id_bytes():
    out = encode(salt=generate_salt(), blob=BLOB, **FAST)
    assert out[6] == FORMAT_VERSION
    assert out[7] == KDF_ID


def test_salt_is_in_header():
    salt = generate_salt()
    out = encode(salt=salt, blob=BLOB, **FAST)
    assert out[16:32] == salt


def test_memory_and_iterations_fields():
    out = encode(salt=generate_salt(), blob=BLOB, **FAST)
    assert int.from_bytes(out[8:12], "big") == MIN_MEMORY_BYTES
    assert int.from_bytes(out[12:16], "big") == MIN_ITERATIONS


def test_body_follows_header():
    out = encode(salt=generate_salt(), blob=BLOB, **FAST)
    assert out[32:] == BLOB


@pytest.mark.parametrize("length", [0, SALT_LENGTH - 1, SALT_LENGTH + 1])
def test_wrong_salt_length_rejected(length):
    with pytest.raises(InvalidParametersError):
        encode(salt=b"\x00" * length, blob=BLOB, **FAST)