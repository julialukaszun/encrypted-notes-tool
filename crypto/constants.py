# sizes (in bytes)
KEY_LENGTH = 32    # 256-bit keys
SALT_LENGTH = 16   # Argon2 salt size

DEFAULT_MEMORY_BYTES = 64 * 1024 * 1024   # 64 MiB
DEFAULT_ITERATIONS = 3

# bounds for validating settings read from an untrusted file header
MIN_MEMORY_BYTES = 16 * 1024 * 1024       # reject weakened settings
MAX_MEMORY_BYTES = 1024 * 1024 * 1024     # reject settings that could crash the program
MIN_ITERATIONS = 2
MAX_ITERATIONS = 10

# file format
MAGIC_BYTES = b"NOTESv"
HEADER_SIZE = 32
MIN_BODY_SIZE = 40
HEADER_FORMAT = '>6sBBII16s'
FORMAT_VERSION = 1
KDF_ID = 1