import click
import requests

from e2ee.cli.get_message import get_decrypted_message
from e2ee.cli.qr import display_qr
from e2ee.cli.save_private_key import save_private_key_to_user_local_machine
from e2ee.cli.utils.state import clear_state, get_state, list_logged_in_users, set_state

BASE_URL = "http://127.0.0.1:5000"  # Adjust if your server is running on a different URL/port
SUCCESS_STATUS_CODE = 200


def _get_only_logged_in_user_or_prompt() -> str:
    logged_in_users = list_logged_in_users()
    if len(logged_in_users) == 1:
        return logged_in_users[0]
    return click.prompt("Enter your user ID", type=str)


@click.group()
def cli():
    """Simple CLI for interacting with the API server."""
    pass


@click.command()
def register():
    """
    Register a new user.
    """
    user_id = click.prompt("Enter a phone number to register (10 digits)", type=str)
    password = click.prompt(
        "Enter a password (Password must be at least 10 characters long and contain at least one number, "
        "one letter and one special"
        "character)",
        type=str,
        hide_input=True,
    )
    response = requests.post(f"{BASE_URL}/register", json={"user_id": user_id, "password": password})
    if response.status_code != SUCCESS_STATUS_CODE:
        click.echo("Registration failed: " + str(response.json()))
        return

    click.echo("Response: " + str(response.json()))

    base64_qr_code = response.json().get("qr_code_base64")
    display_qr(base64_qr_code=base64_qr_code, user_id=user_id)

    otp = click.prompt("Enter the OTP sent to your authenticator app", type=str)
    validate_response = requests.post(
        f"{BASE_URL}/validate", json={"user_id": user_id, "password": password, "otp": otp}
    )
    click.echo("Validation Response: " + str(validate_response.json()))
    validate_response_json = validate_response.json()
    if validate_response.status_code != SUCCESS_STATUS_CODE:
        click.echo("Validation failed: " + str(response.json()))
        return

    private_key = validate_response_json.get("private_key")
    save_private_key_to_user_local_machine(user_id=user_id, private_key=private_key)
    token = validate_response.json().get("jwt_token")

    set_state(user_id=user_id, token=token)
    click.echo("Validation successful! You can now send messages.")


@click.command()
def login():
    """
    Login an existing user.
    """
    user_id = click.prompt("Enter your user ID", type=str)
    state = get_state(user_id)
    if state is not None:
        click.echo(f"You are already logged in to {state.user_id}.")
        return

    password = click.prompt("Enter your password", type=str, hide_input=True)
    otp = click.prompt("Enter the OTP from your authenticator app", type=str)
    response = requests.post(f"{BASE_URL}/login", json={"user_id": user_id, "password": password, "otp": otp})

    if response.status_code != SUCCESS_STATUS_CODE:
        click.echo("Login failed: " + str(response.json()))
        return

    token = response.json().get("jwt_token")
    set_state(user_id=user_id, token=token)
    click.echo("Login successful!")
    return


@click.command()
def send_message():
    """
    Send a message to another user.
    """
    user_id = _get_only_logged_in_user_or_prompt()
    state = get_state(user_id)
    if state is None:
        click.echo("You need to login first.")
        return

    target_user_id = click.prompt("Enter the recipient's user ID", type=str)
    message = click.prompt("Enter the message to send", type=str)
    headers = {"Authorization": f"Bearer {state.token}"}
    response = requests.post(
        f"{BASE_URL}/send_message", json={"target_user_id": target_user_id, "message": message}, headers=headers
    )
    click.echo("Response: " + str(response.json()))


@click.command()
def get_messages():
    """
    Retrieve messages for the logged-in user.
    """
    user_id = _get_only_logged_in_user_or_prompt()
    state = get_state(user_id)
    if state is None:
        click.echo("You need to login first.")
        return

    headers = {"Authorization": f"Bearer {state.token}"}
    response = requests.get(f"{BASE_URL}/get_messages", headers=headers)
    messages = response.json().get("messages", [])

    if not messages:
        click.echo("No messages found.")
        return

    click.echo("Messages received:")
    for msg in messages:
        encrypted_message = msg["encrypted_message"]
        encrypted_symmetric_key = msg["encrypted_symmetric_key"]
        click.echo(
            f"From: {msg['sender_id']} | " f"Encrypted Message: {msg['encrypted_message']} | Timestamp: {msg['date']}"
        )
        decrypted_message = get_decrypted_message(
            encrypted_message=encrypted_message,
            encrypted_symmetric_key=encrypted_symmetric_key,
            user_id=state.user_id,
        )
        click.echo(f"Decrypted Message: {decrypted_message})")


@click.command()
def logout():
    """Logs out all active users"""
    clear_state()
    click.echo("Logged out.")


# Add all commands to the main CLI group
cli.add_command(register)
cli.add_command(login)
cli.add_command(send_message)
cli.add_command(get_messages)
cli.add_command(logout)

if __name__ == "__main__":
    cli()
