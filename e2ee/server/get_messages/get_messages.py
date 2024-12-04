from e2ee.server.api_models import GetMessagesResponse
from e2ee.server.db_actions.message import get_messages, reset_messages


def get_messages_for_user(user_id: str) -> GetMessagesResponse:
    """
    Get all messages for the given user ID.
    """
    messages = get_messages(user_id)
    # Reset the messages after they have been retrieved
    reset_messages(user_id)
    return GetMessagesResponse(message="Messages retrieved", messages=messages)
