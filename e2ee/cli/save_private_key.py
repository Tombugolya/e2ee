from cryptography.hazmat.primitives import serialization

from e2ee.cli.utils.files import get_private_key_path_by_user_id


def save_private_key_to_user_local_machine(user_id: str, private_key: str) -> None:
    """
    Saves the private key to the user's local machine.
    """
    with open(get_private_key_path_by_user_id(user_id), "wb") as private_key_file:
        private_key_file.write(
            serialization.load_pem_private_key(private_key.encode(), password=None).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
