# storage.py - WORK IN PROGRESS!!!

import io
import os
import json
import tempfile
from pathlib import Path
from crypto.cipher import encrypt
from crypto.errors import StorageError
from crypto.file_format import encode
from crypto.kdf import generate_salt, derive_key
from crypto.constants import DEFAULT_MEMORY_BYTES, DEFAULT_ITERATIONS

# helper function for crash safety
# write bytes to a file so the file is never half-written or corrupted
def write(path: Path, data: bytes) -> None:
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    except OSError:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)
        raise StorageError("could not write file") from None

def create(path: Path, password: str, data: dict) -> None:

    if os.path.exists(path):
        raise StorageError("file already exists")

    salt = generate_salt()
    key = derive_key(password, salt, DEFAULT_MEMORY_BYTES, DEFAULT_ITERATIONS)
    plaintext = json.dumps(data).encode("utf-8")
    blob = encrypt(key, plaintext)
    file_bytes = encode(salt, DEFAULT_MEMORY_BYTES, DEFAULT_ITERATIONS, blob)

    write(path, file_bytes) # call helper function




