class CryptoError(Exception):
    """base class for every error raised by the crypto module"""


class DecryptionError(CryptoError):
    """wrong key, wrong password, or tampered/corrupted data"""


class InvalidParametersError(CryptoError):
    """bad salt length, or KDF settings outside the allowed bounds"""

class FormatError(CryptoError):
    """bad magic bytes, unsupported version, unsupported KDF id, and truncated files"""