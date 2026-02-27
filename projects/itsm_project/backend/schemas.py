from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Ticket(BaseModel):
    id: int
    title: str
    description: str
    priority: str
    category: Optional[str] = ""
    status: str
    resolution: Optional[str] = None
    closed_at: Optional[datetime] = None


class User(BaseModel):
    username: str
    name: str
    active: bool
    locked: bool
    password_reset: bool
    last_reset: Optional[datetime] = None


class ClassificationRequest(BaseModel):
    description: str


class ActionRequest(BaseModel):
    username: str


class CloseTicketRequest(BaseModel):
    ticket_id: int
    resolution: str
