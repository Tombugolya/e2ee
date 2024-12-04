from functools import wraps

from flask import request

from e2ee.server.exceptions import InvalidAPIUsageError
from e2ee.server.utils.jwt_token import verify_jwt_token

AUTHORIZATION_HEADER = "Authorization"
BEARER_PREFIX = "Bearer "


def token_required(func):
    """
    Decorator to check if the JWT token is present in the request headers.
    Used to protect the `/send_message` and `/get_messages` endpoints.
    """

    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get(AUTHORIZATION_HEADER)
        if not token:
            raise InvalidAPIUsageError("Token is missing, authentication required", status_code=403)
        try:
            token = token.replace(BEARER_PREFIX, "")
            decoded_token = verify_jwt_token(token)
            if not decoded_token:
                raise ValueError("Invalid")
            # Add the user_id to the request object
            request.user_id = decoded_token["user_id"]
        except ValueError as e:
            raise InvalidAPIUsageError("Invalid or expired token", status_code=403) from e
        return func(*args, **kwargs)

    return decorated
