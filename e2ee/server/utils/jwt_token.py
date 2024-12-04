import os
from datetime import datetime, timedelta, timezone

import jwt

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
TOKEN_EXPIRATION_IN_HOURS = os.getenv("TOKEN_EXPIRATION_IN_HOURS", 1)


def generate_jwt_token(user_id: str) -> str:
    """
    Generate a JWT token for the given user_id.
    """
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRATION_IN_HOURS),  # Token expiration time
        "iat": datetime.now(timezone.utc),  # Issued at time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


def verify_jwt_token(token: str) -> dict:
    """
    Verify the given JWT token.
    """
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded_token  # Return the decoded token if verification succeeds
    except jwt.ExpiredSignatureError as e:
        raise ValueError("Token has expired") from e
    except jwt.InvalidTokenError as e:
        raise ValueError("Invalid token") from e
