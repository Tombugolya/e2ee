from dataclasses import dataclass

from e2ee.server.data_models import Message


@dataclass
class ApiResponse:
    """
    Base class for API responses.
    """

    message: str


@dataclass
class RegisterUserResponse(ApiResponse):
    """
    Response for the register user API
    """

    user_id: str
    qr_code_base64: str


@dataclass
class ValidateUserResponse(ApiResponse):
    """
    Response for the validate user API
    """

    user_id: str
    private_key: str
    jwt_token: str


@dataclass
class LoginUserResponse(ApiResponse):
    """
    Response for the login user API
    """

    jwt_token: str


@dataclass
class GetMessagesResponse(ApiResponse):
    messages: list[Message]
