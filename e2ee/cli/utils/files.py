import os

from e2ee.constants import PRIVATE_KEY_NAME_TEMPLATE, PRIVATE_KEY_PATH, Path


def get_private_key_path_by_user_id(user_id: str) -> Path:
    return os.path.join(PRIVATE_KEY_PATH, PRIVATE_KEY_NAME_TEMPLATE.format(user_id=user_id))
