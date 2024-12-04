import os

from flask import Flask, Response, jsonify, request

from e2ee.server.decorators import token_required
from e2ee.server.exceptions import InvalidAPIUsageError
from e2ee.server.get_messages.get_messages import get_messages_for_user
from e2ee.server.login_user.login_user import login_user
from e2ee.server.register_user.register_user import register_user
from e2ee.server.send_message.send_message import send_message_to_target
from e2ee.server.validate_user.validate_user import validate_user

app = Flask(__name__)

DEVELOPMENT_MODE = os.getenv("DEVELOPMENT_MODE", True)


# API Endpoints
@app.route("/register", methods=["POST"])
def register() -> Response:
    data = request.json
    user_id, password = data.get("user_id"), data.get("password")
    register_user_response = register_user(user_id=user_id, password=password)
    return jsonify(register_user_response.__dict__)


@app.route("/validate", methods=["POST"])
def validate() -> Response:
    data = request.json
    user_id, password, otp = data.get("user_id"), data.get("password"), data.get("otp")
    validate_user_response = validate_user(user_id=user_id, password=password, otp=otp)
    return jsonify(validate_user_response.__dict__)


@app.route("/login", methods=["POST"])
def login() -> Response:
    data = request.json
    user_id, password, otp = data.get("user_id"), data.get("password"), data.get("otp")
    login_user_response = login_user(user_id=user_id, password=password, otp=otp)
    return jsonify(login_user_response.__dict__)


@app.route("/send_message", methods=["POST"])
@token_required
def send_message() -> Response:
    data = request.json
    target_user_id, message = data.get("target_user_id"), data.get("message")
    sender_id = request.user_id if hasattr(request, "user_id") else None

    if not sender_id:
        raise InvalidAPIUsageError("Invalid sender_id", status_code=403)

    send_message_response = send_message_to_target(message=message, target_user_id=target_user_id, sender_id=sender_id)
    return jsonify(send_message_response.__dict__)


@app.route("/get_messages", methods=["GET"])
@token_required
def get_messages() -> Response:
    user_id = request.user_id if hasattr(request, "user_id") else None

    if not user_id:
        raise InvalidAPIUsageError("Invalid user_id", status_code=403)

    get_messages_response = get_messages_for_user(user_id)
    return jsonify(get_messages_response.__dict__)


@app.errorhandler(InvalidAPIUsageError)
def invalid_api_usage(e: InvalidAPIUsageError) -> tuple:
    return jsonify(e.to_dict()), e.status_code


def run_server():
    app.run(debug=DEVELOPMENT_MODE)


if __name__ == "__main__":
    run_server()
