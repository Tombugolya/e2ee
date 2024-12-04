from e2ee.server.api_models import LoginUserResponse
from e2ee.server.db_actions.user import get_user
from e2ee.server.exceptions import InvalidAPIUsageError
from e2ee.server.utils.jwt_token import generate_jwt_token
from e2ee.server.utils.validate import validate_otp, validate_password


def login_user(user_id: str, password: str, otp: str) -> LoginUserResponse:
    """
    Login the user with the given user_id and password.
    If the password and OTP are correct, return a JWT token used for authentication.
    With the JWT token, the user can send and receive messages, which otherwise would be blocked.
    """
    fetched_user = get_user(user_id)
    if not validate_password(password=password, hashed_password=fetched_user.hashed_password):
        raise InvalidAPIUsageError("Invalid password", status_code=400)
    if not validate_otp(otp=otp, totp_secret=fetched_user.totp_secret):
        raise InvalidAPIUsageError("Invalid OTP", status_code=400)

    return LoginUserResponse(message="Login Successful", jwt_token=generate_jwt_token(user_id))
