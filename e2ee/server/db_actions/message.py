import base64
from datetime import datetime, timezone

from e2ee.constants import MAX_MESSAGES_PER_USER
from e2ee.server.data_models import EncryptedMessageWithEncryptedKey, Message

# A dictionary to store the messages for each user
# This is just for demonstration purposes. In a real-world application, you would use a database to store messages.
_MESSAGES: dict[str, list[Message]] = {}


def save_message(encrypted_user_message: EncryptedMessageWithEncryptedKey, target_user_id: str, sender_id: str) -> None:
    """
    Saves the message for the target user.
    """
    if target_user_id not in _MESSAGES:
        _MESSAGES[target_user_id] = []

    if len(get_messages(target_user_id)) >= MAX_MESSAGES_PER_USER:
        _MESSAGES[target_user_id].pop(0)

    encoded_message = base64.b64encode(encrypted_user_message.encrypted_message).decode("utf-8")
    encoded_symmetric_key = base64.b64encode(encrypted_user_message.encrypted_symmetric_key).decode("utf-8")
    message = Message(
        encrypted_message=encoded_message,
        encrypted_symmetric_key=encoded_symmetric_key,
        sender_id=sender_id,
        date=datetime.now(timezone.utc).isoformat(),
    )

    _MESSAGES[target_user_id].append(message)


def get_messages(user_id: str) -> list[Message]:
    """
    Get all messages for the given user ID and clears them from the message store.
    """
    return _MESSAGES.get(user_id, [])


def reset_messages(user_id: str) -> None:
    """
    Reset the messages for the given user ID.
    """
    _MESSAGES[user_id] = []
