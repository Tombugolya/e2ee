import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from e2ee.constants import IV_LENGTH
from e2ee.server.data_models import EncryptedMessageWithEncryptedKey
from e2ee.server.utils.crypto import encrypt_symmetric_key_with_rsa, generate_symmetric_key


def _generate_iv() -> bytes:
    """
    Generate an initialization vector for the encryption.
    """
    return os.urandom(IV_LENGTH)


def _encrypt_message_with_symmetric_key(message: str, symmetric_key: bytes) -> bytes:
    """
    Encrypt the message with the symmetric key using AES-GCM.
    """
    iv = _generate_iv()
    cipher = Cipher(algorithm=algorithms.AES(symmetric_key), mode=modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # Return IV + ciphertext + tag


def encrypt_user_message(message: str, target_public_key: RSAPublicKey) -> EncryptedMessageWithEncryptedKey:
    """
    Encrypt the message with the given public key, which is the target user's public key.
    :param message: The message to encrypt
    :param target_public_key: The public key of the user receiving the message
    :return: EncryptedMessageResponse which contains the encrypted message and the encrypted symmetric key
    """
    symmetric_key = generate_symmetric_key()

    encrypted_symmetric_key = encrypt_symmetric_key_with_rsa(public_key=target_public_key, symmetric_key=symmetric_key)
    # Encrypt the message with the known symmetric key
    encrypted_message = _encrypt_message_with_symmetric_key(
        message=message,
        symmetric_key=symmetric_key,
    )

    return EncryptedMessageWithEncryptedKey(
        encrypted_message=encrypted_message, encrypted_symmetric_key=encrypted_symmetric_key
    )
