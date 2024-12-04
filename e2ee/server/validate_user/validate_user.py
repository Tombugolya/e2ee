from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from e2ee.server.api_models import ApiResponse, ValidateUserResponse
from e2ee.server.db_actions.public_key import write_public_key
from e2ee.server.db_actions.user import get_user, update_user_validation
from e2ee.server.exceptions import InvalidAPIUsageError
from e2ee.server.utils.crypto import generate_rsa_key_pair
from e2ee.server.utils.jwt_token import generate_jwt_token
from e2ee.server.utils.validate import validate_otp, validate_password


def _decode_private_key(private_key: RSAPrivateKey) -> str:
    """
    Decode the private key to a string to be sent to the user.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def validate_user(user_id: str, password: str, otp: str) -> ApiResponse:
    """
    Validate the user with the given user ID, password and OTP.

    For E2EE each user needs to have an RSA key pair - One public key which is shared with other users
    and one private key which will be kept secret and downloaded by the user to his local machine.

    If the user is validated, generate an RSA key pair for the user, save the public key to the DB, return the
    private key to the user, and update the user's validation status to True.
    """
    fetched_user = get_user(user_id)

    # Exit early if the user is already validated
    if fetched_user.is_validated:
        return ApiResponse(message="User already validated")

    if not validate_password(password=password, hashed_password=fetched_user.hashed_password):
        raise InvalidAPIUsageError("Invalid password", status_code=400)
    if not validate_otp(otp=otp, totp_secret=fetched_user.totp_secret):
        raise InvalidAPIUsageError("Invalid OTP", status_code=400)

    # Now that the user is validate, we can generate the RSA Key Pair for the user, save the public key to the DB
    # and return the private key to the user.
    user_key_pair = generate_rsa_key_pair()
    write_public_key(user_id=user_id, user_key_pair=user_key_pair)

    # Update the user's validation status to True
    update_user_validation(user_id=user_id, is_validated=True)

    # Return the private key to the user
    return ValidateUserResponse(
        message="User validated successfully",
        user_id=user_id,
        private_key=_decode_private_key(user_key_pair.private_key),
        jwt_token=generate_jwt_token(user_id),
    )
