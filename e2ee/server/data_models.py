from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


@dataclass
class EncryptedMessageWithEncryptedKey:
    """
    A data class to hold an encrypted message and the encrypted symmetric key used to encrypt the message.
    """

    encrypted_message: bytes
    encrypted_symmetric_key: bytes


@dataclass
class TotpSecret:
    """
    A data class to hold the base64 encoded QR code and the secret used to generate
    """

    qr_code_base64: str
    secret: str


@dataclass
class RSAKeyPair:
    """
    A data class to hold an RSA key pair.
    """

    private_key: RSAPrivateKey
    public_key: RSAPublicKey


@dataclass
class DatabaseModel:
    """
    A base class for all database models
    """

    pass


@dataclass
class User(DatabaseModel):
    """
    Represents a user in the database.
    """

    user_id: str
    hashed_password: str
    totp_secret: str
    is_validated: bool
    created_at: str


@dataclass
class Message:
    """
    Represents a message sent from one user to another.
    """

    encrypted_message: str
    encrypted_symmetric_key: str
    sender_id: str
    date: str
