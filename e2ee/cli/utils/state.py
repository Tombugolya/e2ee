import json
import os
from dataclasses import dataclass

SESSION_FILE = "e2ee_session.json"


@dataclass
class State:
    user_id: str
    token: str


def _load_session() -> dict[str, str]:
    """
    Load the session file into a dictionary.
    """
    if not os.path.exists(SESSION_FILE):
        return {}
    with open(SESSION_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_session(session: dict[str, str]) -> None:
    """
    Save the session dictionary to the file.
    """
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(session, f)


def set_state(user_id: str, token: str) -> None:
    """
    Save the state for a specific user.
    """
    session = _load_session()
    session[user_id] = token
    _save_session(session)


def clear_state(user_id: str | None = None) -> None:
    """
    Clear the state for a specific user or all users.
    """
    if user_id:
        session = _load_session()
        if user_id in session:
            del session[user_id]
            _save_session(session)
    else:
        # Clear all sessions
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)


def get_state(user_id: str) -> State | None:
    """
    Get the state for a specific user.
    """
    session = _load_session()
    if user_id in session:
        return State(user_id=user_id, token=session[user_id])
    return None


def list_logged_in_users() -> list[str]:
    """
    List all currently logged-in users and their tokens.
    """
    session = _load_session()
    return list(session.keys())
