import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data"
TICKETS_PATH = DATA_DIR / "tickets.json"
USERS_PATH = DATA_DIR / "users.json"


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def _find_user(username: str, users: List[Dict[str, Any]]) -> Dict[str, Any]:
    for user in users:
        if user.get("username") == username:
            return user
    raise ValueError(f"User '{username}' not found")


def _find_ticket(ticket_id: int, tickets: List[Dict[str, Any]]) -> Dict[str, Any]:
    for ticket in tickets:
        if ticket.get("id") == ticket_id:
            return ticket
    raise ValueError(f"Ticket '{ticket_id}' not found")


def reset_password(username: str) -> Dict[str, Any]:
    users = _load_json(USERS_PATH)
    user = _find_user(username, users)
    user["password_reset"] = True
    user["last_reset"] = datetime.now(timezone.utc).isoformat()
    _write_json(USERS_PATH, users)
    logger.info("Password reset simulated for user=%s", username)
    return user


def activate_user(username: str) -> Dict[str, Any]:
    users = _load_json(USERS_PATH)
    user = _find_user(username, users)
    user["active"] = True
    _write_json(USERS_PATH, users)
    logger.info("User activated user=%s", username)
    return user


def unlock_user(username: str) -> Dict[str, Any]:
    users = _load_json(USERS_PATH)
    user = _find_user(username, users)
    user["locked"] = False
    _write_json(USERS_PATH, users)
    logger.info("User unlocked user=%s", username)
    return user


def close_ticket(ticket_id: int, resolution: str) -> Dict[str, Any]:
    tickets = _load_json(TICKETS_PATH)
    ticket = _find_ticket(ticket_id, tickets)
    ticket["status"] = "closed"
    ticket["resolution"] = resolution
    ticket["closed_at"] = datetime.now(timezone.utc).isoformat()
    _write_json(TICKETS_PATH, tickets)
    logger.info("Ticket closed ticket_id=%s resolution=%s", ticket_id, resolution)
    return ticket
