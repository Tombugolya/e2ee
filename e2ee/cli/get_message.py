from base64 import b64decode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from e2ee.cli.utils.files import get_private_key_path_by_user_id
from e2ee.cli.utils.message_decryption import decrypt_user_message


def _get_private_key_from_user_id(user_id: str) -> RSAPrivateKey:
    """
    Retrieve the private key of the user with the given user ID from local machine.
    This function assumes that it is being called by the recipient of the message locally.
    """
    with open(get_private_key_path_by_user_id(user_id), "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def get_decrypted_message(encrypted_message: str, encrypted_symmetric_key: str, user_id: str) -> str:
    """
    Decrypt the encrypted message with the recipient's private key.
    This function assumes that it is being called by the recipient of the message locally.
    :param encrypted_message: The encrypted message to decrypt.
    :param encrypted_symmetric_key: The encrypted symmetric key used to encrypt the message.
    :param user_id: The user ID of the recipient.
    :return: The decrypted message.
    """
    recipient_private_key = _get_private_key_from_user_id(user_id=user_id)
    # both the message and symmetric key are base64 encoded, so we need to decode it first
    encoded_encrypted_message = b64decode(encrypted_message)
    encoded_encrypted_symmetric_key = b64decode(encrypted_symmetric_key)

    return decrypt_user_message(
        encrypted_message=encoded_encrypted_message,
        encrypted_symmetric_key=encoded_encrypted_symmetric_key,
        recipient_private_key=recipient_private_key,
    )
