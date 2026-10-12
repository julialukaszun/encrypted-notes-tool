from crypto.errors import CryptoError, DecryptionError, InvalidParametersError


def test_decryption_error_is_crypto_error():
    assert issubclass(DecryptionError, CryptoError)


def test_invalid_parameters_error_is_crypto_error():
    assert issubclass(InvalidParametersError, CryptoError)
