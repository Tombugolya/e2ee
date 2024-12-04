from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from e2ee.server.utils.crypto import RSAKeyPair
from e2ee.server.utils.files import get_public_key_path_by_user_id


def get_public_key(user_id: str) -> RSAPublicKey:
    """
    Retrieves the public key of the user with the given user ID.
    """
    with open(get_public_key_path_by_user_id(user_id), "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())
    return public_key


def write_public_key(user_id: str, user_key_pair: RSAKeyPair) -> None:
    """
    Write the public key of the user to the DB, which in our case is just a file.
    """
    with open(get_public_key_path_by_user_id(user_id), "wb") as public_key_file:
        public_key_file.write(
            user_key_pair.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
