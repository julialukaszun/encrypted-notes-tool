import pytest

from crypto.constants import (
    KEY_LENGTH, SALT_LENGTH,
    MIN_MEMORY_BYTES, MAX_MEMORY_BYTES,
    MIN_ITERATIONS, MAX_ITERATIONS,
)
from crypto.errors import InvalidParametersError
from crypto.kdf import derive_key, generate_salt

# Use the cheapest allowed settings so the tests run fast.
FAST = dict(memory_bytes=MIN_MEMORY_BYTES, iterations=MIN_ITERATIONS)


# ---------- generate_salt ----------

def test_salt_has_correct_length():
    assert len(generate_salt()) == SALT_LENGTH


def test_two_salts_differ():
    assert generate_salt() != generate_salt()


# ---------- derive_key: normal behavior ----------

def test_key_has_correct_length():
    key = derive_key("password", generate_salt(), **FAST)
    assert len(key) == KEY_LENGTH


def test_same_inputs_give_same_key():
    salt = generate_salt()
    assert derive_key("password", salt, **FAST) == derive_key("password", salt, **FAST)


def test_different_salt_gives_different_key():
    assert derive_key("password", generate_salt(), **FAST) != \
           derive_key("password", generate_salt(), **FAST)


def test_different_password_gives_different_key():
    salt = generate_salt()
    assert derive_key("password1", salt, **FAST) != derive_key("password2", salt, **FAST)


def test_one_character_difference_gives_different_key():
    salt = generate_salt()
    assert derive_key("password", salt, **FAST) != derive_key("passwore", salt, **FAST)


def test_different_params_give_different_key():
    salt = generate_salt()
    a = derive_key("password", salt, MIN_MEMORY_BYTES, MIN_ITERATIONS)
    b = derive_key("password", salt, MIN_MEMORY_BYTES, MIN_ITERATIONS + 1)
    assert a != b


def test_unicode_normalization():
    # Same visible text, two different byte representations.
    precomposed = "caf\u00e9"      # e with accent as one character
    decomposed = "cafe\u0301"      # e followed by a combining accent
    assert precomposed != decomposed
    salt = generate_salt()
    assert derive_key(precomposed, salt, **FAST) == derive_key(decomposed, salt, **FAST)


# ---------- derive_key: bad inputs ----------

@pytest.mark.parametrize("length", [0, SALT_LENGTH - 1, SALT_LENGTH + 1])
def test_wrong_salt_length_rejected(length):
    with pytest.raises(InvalidParametersError):
        derive_key("password", b"\x00" * length, **FAST)


@pytest.mark.parametrize("memory", [MIN_MEMORY_BYTES - 1, MAX_MEMORY_BYTES + 1])
def test_memory_out_of_range_rejected(memory):
    with pytest.raises(InvalidParametersError):
        derive_key("password", generate_salt(), memory_bytes=memory, iterations=MIN_ITERATIONS)


@pytest.mark.parametrize("iterations", [MIN_ITERATIONS - 1, MAX_ITERATIONS + 1])
def test_iterations_out_of_range_rejected(iterations):
    with pytest.raises(InvalidParametersError):
        derive_key("password", generate_salt(), memory_bytes=MIN_MEMORY_BYTES, iterations=iterations)
