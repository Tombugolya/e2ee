from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from e2ee.constants import IV_LENGTH, TAG_LENGTH


def _decrypt_message(encrypted_message: bytes, decrypted_symmetry_key: bytes) -> str:
    """
    Decrypt the message with the symmetric key using AES-GCM.
    """
    iv = encrypted_message[:IV_LENGTH]
    tag = encrypted_message[IV_LENGTH : IV_LENGTH + TAG_LENGTH]
    ciphertext = encrypted_message[IV_LENGTH + TAG_LENGTH :]

    cipher = Cipher(
        algorithm=algorithms.AES(decrypted_symmetry_key), mode=modes.GCM(iv, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()


def _decrypt_symmetric_key_with_rsa(encrypted_symmetric_key: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decrypt the symmetric key with the RSA private key.
    """
    return private_key.decrypt(
        ciphertext=encrypted_symmetric_key,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_user_message(
    encrypted_message: bytes, encrypted_symmetric_key: bytes, recipient_private_key: RSAPrivateKey
) -> str:
    """
    Decrypt the message with the given private key.
    :param encrypted_symmetric_key: Encrypted symmetric key as bytes
    :param encrypted_message: EncryptedMessageResponse dataclass
    :param recipient_private_key: RSAPrivateKey of the user receiving the message
    :return: Decrypted message as a string
    """
    # Decrypt the symmetric key with User B's private key
    decrypted_symmetric_key = _decrypt_symmetric_key_with_rsa(
        private_key=recipient_private_key, encrypted_symmetric_key=encrypted_symmetric_key
    )
    # Decrypt the message with the decrypted symmetric key
    return _decrypt_message(encrypted_message=encrypted_message, decrypted_symmetry_key=decrypted_symmetric_key)
