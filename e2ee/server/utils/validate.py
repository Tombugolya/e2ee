import bcrypt
import pyotp


def validate_otp(otp: str, totp_secret: str) -> bool:
    """
    Validate the OTP against the TOTP secret.
    """
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(otp)


def validate_password(password: str, hashed_password: str) -> bool:
    """
    Validate the password against the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password.encode())
