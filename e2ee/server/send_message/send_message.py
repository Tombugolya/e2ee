from e2ee.server.api_models import ApiResponse
from e2ee.server.db_actions.message import save_message
from e2ee.server.db_actions.public_key import get_public_key
from e2ee.server.utils.message_encryption import encrypt_user_message


def send_message_to_target(message: str, target_user_id: str, sender_id: str) -> ApiResponse:
    """
    This function encrypts the message and sends it to the target user.

    The message is encrypted using a randomly generated symmetric key, which is then encrypted using the target user's
    public key.

    The encrypted message and the encrypted symmetric key are then encoded to base64 and sent to the target
    user.
    """
    public_key = get_public_key(user_id=target_user_id)
    encrypted_user_message = encrypt_user_message(message=message, target_public_key=public_key)
    save_message(encrypted_user_message=encrypted_user_message, target_user_id=target_user_id, sender_id=sender_id)
    return ApiResponse(message="Message sent successfully")
