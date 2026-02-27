# ITSM L1 Automator

Practical project oriented toward an **IT Support Analyst / Level 1 Service Desk** role.  
It simulates the basic incident handling lifecycle: ticket intake, initial classification, execution of typical L1 actions, and closure with documented resolution.

The goal of this project is to demonstrate real understanding of **ITSM workflows**, user support processes, and common support operations in corporate environments.

---

## Typical Support Flow (L1)

1. A user reports an incident (ticket).
2. The system suggests an initial classification based on the description.
3. The analyst performs common Level 1 IT Support actions.
4. The ticket is documented and closed with a resolution.

---

## What This Project Demonstrates

- Basic ticket management and resolution status handling.
- Execution of common Level 1 IT Support actions (password reset, user activation, account unlock).
- Initial incident classification using keyword-based logic.
- Ticket visualization and operational metrics in a dashboard.
- API-based service consumption through REST endpoints.

---

## Main Features

- FastAPI backend with L1 actions (password reset, user activation, account unlock, and ticket closure).
- Keyword-based classification engine.
- Dashboard developed in Streamlit with ticket table and metrics panel.
- Sample data in JSON format for tickets and users.
- REST-ready endpoints.

---

## Installation and Execution

### Backend (FastAPI)

1. Create a virtual environment (optional) and install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the server:

```bash
uvicorn backend.app:app --reload --port 8000
```

3. Interactive documentation available at:  
`http://localhost:8000/docs`

---

### Frontend (Streamlit)

1. In another terminal, run the dashboard:

```bash
streamlit run frontend/dashboard.py
```

2. If the backend is not running on `http://localhost:8000`, set the environment variable:

```bash
$env:API_BASE_URL="http://<host>:<port>"
streamlit run frontend/dashboard.py
```

---

## Example Endpoints

### List tickets
`GET /tickets`

### Classify ticket (suggestion)
`POST /classify`

```json
{ "description": "I cannot log into the system" }
```

### Reset password
`POST /actions/reset-password`

```json
{ "username": "jperez" }
```

### Activate user
`POST /actions/activate-user`

```json
{ "username": "mlopez" }
```

### Unlock account
`POST /actions/unlock-account`

```json
{ "username": "lmartinez" }
```

### Close ticket
`POST /actions/close-ticket`

```json
{ "ticket_id": 1, "resolution": "Password reset completed" }
```

---

## Repository Structure

```text
itsm-l1-automator/
├── backend/
│   ├── app.py
│   ├── classifier.py
│   ├── actions.py
│   ├── schemas.py
│   └── data/
│       ├── tickets.json
│       └── users.json
├── frontend/
│   └── dashboard.py
├── README.md
└── requirements.txt
```

---

## Roadmap (Future Improvements)

- Database persistence and action auditing.
- Basic backend authentication and access control.
- Ticket creation and editing from the dashboard.
- Integration with real ITSM tools (Jira, ServiceNow, etc.).
- Automated testing (unit and end-to-end).
## Final Notes
- Data in JSON is simulated and can be manually reset for new testing.
- Classification uses a simple keyword heuristic; can be extended with more complex rules or ML.
- The board is intended for local demonstrations; adjust `API_BASE_URL` according to the deployment environment.
