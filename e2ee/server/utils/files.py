import os

from e2ee.constants import (
    PUBLIC_KEY_NAME_TEMPLATE,
    PUBLIC_KEYS_PATH,
    USER_FILE_NAME_TEMPLATE,
    USERS_PATH,
    Path,
)


def get_public_key_path_by_user_id(user_id: str) -> Path:
    return os.path.join(PUBLIC_KEYS_PATH, PUBLIC_KEY_NAME_TEMPLATE.format(user_id=user_id))


def user_file_path(user_id: str) -> Path:
    return os.path.join(USERS_PATH, USER_FILE_NAME_TEMPLATE.format(user_id=user_id))
