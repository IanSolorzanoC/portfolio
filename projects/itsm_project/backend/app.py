import logging
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import actions, classifier, schemas

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="ITSM L1 Automator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path(__file__).parent / "data"
TICKETS_PATH = DATA_DIR / "tickets.json"


def _load_tickets() -> List[schemas.Ticket]:
    import json

    with TICKETS_PATH.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [schemas.Ticket(**ticket) for ticket in raw]


@app.get("/tickets", response_model=List[schemas.Ticket])
def get_tickets() -> List[schemas.Ticket]:
    logger.info("Fetching tickets")
    return _load_tickets()


@app.post("/classify")
def classify_ticket(request: schemas.ClassificationRequest) -> dict:
    suggested = classifier.classify_description(request.description)
    logger.info("Classification suggested category=%s", suggested)
    return {"suggested_category": suggested}


@app.post("/actions/reset-password")
def reset_password(request: schemas.ActionRequest) -> schemas.User:
    try:
        return schemas.User(**actions.reset_password(request.username))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/actions/activate-user")
def activate_user(request: schemas.ActionRequest) -> schemas.User:
    try:
        return schemas.User(**actions.activate_user(request.username))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/actions/unlock-account")
def unlock_account(request: schemas.ActionRequest) -> schemas.User:
    try:
        return schemas.User(**actions.unlock_user(request.username))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/actions/close-ticket")
def close_ticket(request: schemas.CloseTicketRequest) -> schemas.Ticket:
    try:
        return schemas.Ticket(**actions.close_ticket(request.ticket_id, request.resolution))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=True)
