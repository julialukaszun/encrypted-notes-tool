# file_format.py
import struct
from typing import Tuple, Any
from crypto.constants import (SALT_LENGTH, MAGIC_BYTES, FORMAT_VERSION,
                              KDF_ID, HEADER_FORMAT, HEADER_SIZE, MIN_BODY_SIZE)
from crypto.errors import InvalidParametersError, FormatError


def encode(salt: bytes, memory_bytes: int, iterations: int, blob: bytes) -> bytes:
    if len(salt) != SALT_LENGTH:
        raise InvalidParametersError("invalid salt length") from None

    try: # magic bytes (6), format version (1), KDF id (1), memory cost (4), iterations (4), salt (16)
        header = struct.pack(HEADER_FORMAT,MAGIC_BYTES, FORMAT_VERSION, KDF_ID, memory_bytes, iterations, salt)
    except struct.error:
        raise InvalidParametersError("header field out of range") from None

    return header + blob # blob is body

def decode(data: bytes) -> tuple[bytes, int, int, bytes]:

    if len(data) < HEADER_SIZE + MIN_BODY_SIZE:
        raise FormatError("file too short")

    magic_bytes, format_version, kdf_id, memory_bytes, iterations, salt = struct.unpack_from(HEADER_FORMAT, data)

    if magic_bytes != MAGIC_BYTES:
        raise FormatError("invalid magic bytes")
    if format_version != FORMAT_VERSION:
        raise FormatError("invalid format version")
    if kdf_id != KDF_ID:
        raise FormatError("unsupported key derivation method")

    blob = bytes(data[HEADER_SIZE:]) # body

    return salt, memory_bytes, iterations, blob


