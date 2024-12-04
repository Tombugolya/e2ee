import os
from typing import LiteralString

# Type alias for file path
Path = LiteralString | str | bytes

# Represents the name of the directory where the we will store the "db" data.
DB_DIR = "db"

# Represents the path to the directory where the public keys are stored.
PUBLIC_KEYS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_DIR, "public_keys")

# Represents the name of the public key file template. The user ID will be formatted into this string.
PUBLIC_KEY_NAME_TEMPLATE = "public-key-{user_id}.pem"

# Represents the path to the directory where the private key is stored.
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# Represents the name of the private key file template. The user ID will be formatted into this string.
PRIVATE_KEY_NAME_TEMPLATE = "private-key-{user_id}.pem"

# Represents the path to the directory where the user data is stored.
USERS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_DIR, "users")

# Represents the name of the user file template. The user ID will be formatted into this string.
USER_FILE_NAME_TEMPLATE = "user-{user_id}.json"

# Represents the length of the initialization vector (IV) used in the AES encryption.
IV_LENGTH = 16

# Represents the length of the tag used in the AES-GCM encryption.
TAG_LENGTH = 16

# Max messages per user
MAX_MESSAGES_PER_USER = 10
