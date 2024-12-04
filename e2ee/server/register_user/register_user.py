import base64
from io import BytesIO

import bcrypt
import pyotp
from qrcode.main import QRCode

from e2ee.server.api_models import RegisterUserResponse
from e2ee.server.data_models import TotpSecret
from e2ee.server.db_actions.user import write_user
from e2ee.server.exceptions import InvalidAPIUsageError

PHONE_NUMBER_LENGTH = 10
PASSWORD_MIN_LENGTH = 10


def _validate_user_id(user_id: str) -> str:
    """
    Validate the user ID.
    It should be a valid phone number, which we will represent as a 10-digit string.
    """
    if not user_id.isdigit() or len(user_id) != PHONE_NUMBER_LENGTH:
        raise InvalidAPIUsageError("Invalid phone number", status_code=400)
    return user_id


def _validate_and_hash_password(password: str) -> bytes:
    """
    Validates the password and hashes it using bcrypt.
    The password must be at a sufficient character length and contain at least one number, one letter and one special
    """
    if not all(
        [
            any(char.isdigit() for char in password),
            any(char.isalpha() for char in password),
            any(not char.isalnum() for char in password),
            len(password) >= PASSWORD_MIN_LENGTH,
        ]
    ):
        raise InvalidAPIUsageError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters long and contain at least one number, "
            f"one letter and one special"
            "character.",
            status_code=400,
        )

    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_totp_secret(user_id: str) -> TotpSecret:
    """
    Generate a TOTP secret for the user with the given user ID.
    The TOTP secret is used to generate a QR code which the user can scan to set up their TOTP.
    """
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    qr_code_url = totp.provisioning_uri(name=user_id, issuer_name="artiom_bogulia_e2ee_project")
    # Generate the QR code using qrcode library
    qr = QRCode()
    qr.add_data(qr_code_url)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    # Convert the image to a base64 string
    buffered = BytesIO()
    img.save(buffered)
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return TotpSecret(secret=totp_secret, qr_code_base64=qr_code_base64)


def register_user(user_id: str, password: str) -> RegisterUserResponse:
    """
    Register a user with the given ID and password.

    The password is hashed using bcrypt (with a salt) and the hashed password is stored in the database.

    A TOTP Secret (Time-based One-Time Password) is generated for the user and stored in the database, this
    is used to generate a QR code which the user can scan to set up their TOTP, this is used as a second factor
    of authentication.
    """
    # Validate the user ID and password
    validated_user_id = _validate_user_id(user_id)
    hashed_password = _validate_and_hash_password(password)
    totp_secret = _generate_totp_secret(validated_user_id)

    # Save the user to the database with the hashed password and TOTP secret and in a non-validated state
    write_user(
        user_id=validated_user_id,
        hashed_password=hashed_password.decode(),
        totp_secret=totp_secret.secret,
        is_validated=False,
    )
    return RegisterUserResponse(
        message="Registered successfully", qr_code_base64=totp_secret.qr_code_base64, user_id=validated_user_id
    )
