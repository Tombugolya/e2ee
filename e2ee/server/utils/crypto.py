import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from e2ee.server.data_models import RSAKeyPair


def generate_rsa_key_pair() -> RSAKeyPair:
    """
    Generate an RSA key pair for encryption and decryption.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return RSAKeyPair(private_key=private_key, public_key=public_key)


def generate_symmetric_key() -> bytes:
    """
    Generate a symmetric key for encryption.
    This generates a 256-bit symmetric key (32 bytes)
    """
    return os.urandom(32)


def encrypt_symmetric_key_with_rsa(
    symmetric_key: bytes,
    public_key: RSAPublicKey,
) -> bytes:
    """
    Encrypt the symmetric key with the RSA public key.
    """
    return public_key.encrypt(
        plaintext=symmetric_key,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
