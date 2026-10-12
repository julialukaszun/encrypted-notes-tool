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

# file format (used later by the format module)
MAGIC_BYTES = b"NOTESv"
FORMAT_VERSION = 1