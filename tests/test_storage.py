import json
import os
import sys

import pytest

from crypto.constants import MIN_ITERATIONS, MIN_MEMORY_BYTES
from crypto.cipher import decrypt
from crypto.errors import StorageError
from crypto.file_format import decode
from crypto.kdf import derive_key
import crypto.storage as st


PASSWORD = "correct horse battery staple"
DATA = {"version": 1, "notes": [{"id": 1, "title": "bank", "text": "hunter2-secret"}]}

windows_only_skip = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file permissions don't apply on Windows"
)


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Use the cheapest Argon2 settings so each test runs quickly."""
    monkeypatch.setattr(st, "DEFAULT_MEMORY_BYTES", MIN_MEMORY_BYTES)
    monkeypatch.setattr(st, "DEFAULT_ITERATIONS", MIN_ITERATIONS)


def read_back(path, password=PASSWORD):
    """Open a file by hand (without load) to check what create wrote."""
    salt, memory_bytes, iterations, blob = decode(path.read_bytes())
    key = derive_key(password, salt, memory_bytes, iterations)
    return json.loads(decrypt(key, blob))


def leftover_temp_files(folder):
    return [p for p in folder.iterdir() if p.name.endswith(".tmp")]


# ====================== _write_atomic ======================

def test_write_atomic_writes_bytes_to_new_file(tmp_path):
    target = tmp_path / "out.bin"
    st._write_atomic(target, b"hello")
    assert target.read_bytes() == b"hello"


def test_write_atomic_replaces_existing_file(tmp_path):
    target = tmp_path / "out.bin"
    target.write_bytes(b"old content")
    st._write_atomic(target, b"new content")
    assert target.read_bytes() == b"new content"


def test_write_atomic_handles_empty_data(tmp_path):
    target = tmp_path / "out.bin"
    st._write_atomic(target, b"")
    assert target.read_bytes() == b""


@windows_only_skip
def test_write_atomic_sets_owner_only_permissions(tmp_path):
    target = tmp_path / "out.bin"
    st._write_atomic(target, b"hello")
    assert target.stat().st_mode & 0o777 == 0o600


def test_write_atomic_leaves_no_temp_files_on_success(tmp_path):
    target = tmp_path / "out.bin"
    st._write_atomic(target, b"hello")
    assert [p.name for p in tmp_path.iterdir()] == ["out.bin"]


def test_write_atomic_failure_keeps_original_file(tmp_path, monkeypatch):
    target = tmp_path / "out.bin"
    target.write_bytes(b"precious original")

    def boom(*args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(StorageError):
        st._write_atomic(target, b"new content")

    assert target.read_bytes() == b"precious original"


def test_write_atomic_failure_leaves_no_temp_files(tmp_path, monkeypatch):
    target = tmp_path / "out.bin"
    target.write_bytes(b"precious original")

    def boom(*args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(StorageError):
        st._write_atomic(target, b"new content")

    assert leftover_temp_files(tmp_path) == []


def test_write_atomic_missing_parent_folder_raises_storage_error(tmp_path):
    target = tmp_path / "no_such_folder" / "out.bin"
    with pytest.raises(StorageError):
        st._write_atomic(target, b"hello")


# ====================== create ======================

def test_create_writes_readable_encrypted_file(tmp_path):
    path = tmp_path / "notes.enc"
    st.create(path, PASSWORD, DATA)
    assert read_back(path) == DATA


def test_create_file_does_not_contain_plaintext(tmp_path):
    path = tmp_path / "notes.enc"
    st.create(path, PASSWORD, DATA)
    raw = path.read_bytes()
    assert b"hunter2-secret" not in raw
    assert b"bank" not in raw


def test_create_existing_file_raises_and_leaves_it_unchanged(tmp_path):
    path = tmp_path / "notes.enc"
    path.write_bytes(b"do not touch")
    with pytest.raises(StorageError):
        st.create(path, PASSWORD, DATA)
    assert path.read_bytes() == b"do not touch"


def test_create_on_a_directory_path_raises(tmp_path):
    # Needs path.exists() rather than path.is_file() in create.
    with pytest.raises(StorageError):
        st.create(tmp_path, PASSWORD, DATA)


def test_create_missing_folder_raises_storage_error(tmp_path):
    path = tmp_path / "no_such_folder" / "notes.enc"
    with pytest.raises(StorageError):
        st.create(path, PASSWORD, DATA)


def test_create_wrong_password_cannot_read_back(tmp_path):
    from crypto.errors import DecryptionError
    path = tmp_path / "notes.enc"
    st.create(path, PASSWORD, DATA)
    with pytest.raises(DecryptionError):
        read_back(path, password="wrong password")


def test_create_two_files_from_same_data_differ(tmp_path):
    a = tmp_path / "a.enc"
    b = tmp_path / "b.enc"
    st.create(a, PASSWORD, DATA)
    st.create(b, PASSWORD, DATA)
    assert a.read_bytes() != b.read_bytes()


def test_create_handles_unicode_data(tmp_path):
    path = tmp_path / "notes.enc"
    data = {"notes": [{"title": "café ☕", "text": "日本語"}]}
    st.create(path, PASSWORD, data)
    assert read_back(path) == data


@windows_only_skip
def test_create_sets_owner_only_permissions(tmp_path):
    path = tmp_path / "notes.enc"
    st.create(path, PASSWORD, DATA)
    assert path.stat().st_mode & 0o777 == 0o600


def test_create_leaves_no_temp_files(tmp_path):
    path = tmp_path / "notes.enc"
    st.create(path, PASSWORD, DATA)
    assert leftover_temp_files(tmp_path) == []