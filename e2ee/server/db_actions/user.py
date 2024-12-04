import json
from datetime import datetime, timezone

from e2ee.server.data_models import User
from e2ee.server.utils.files import user_file_path


def get_user(user_id: str) -> User:
    """
    Get the user details from the user file.
    """
    with open(user_file_path(user_id), "r") as user_file:
        return User(**json.load(user_file))


def write_user(
    user_id: str, hashed_password: str, totp_secret: str, is_validated: bool, created_at: str | None = None
) -> None:
    """
    Write the user to the `users` directory.
    """
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    user_to_write = User(
        user_id=user_id,
        hashed_password=hashed_password,
        totp_secret=totp_secret,
        created_at=created_at,
        is_validated=is_validated,
    )
    with open(user_file_path(user_id), "w") as user_file:
        user_json = json.dumps(user_to_write.__dict__)
        user_file.write(user_json)


def update_user_validation(user_id: str, is_validated: bool) -> None:
    """
    Update the user's validation status.
    """
    user = get_user(user_id)
    write_user(
        user_id=user_id,
        hashed_password=user.hashed_password,
        totp_secret=user.totp_secret,
        created_at=user.created_at,
        is_validated=is_validated,
    )
