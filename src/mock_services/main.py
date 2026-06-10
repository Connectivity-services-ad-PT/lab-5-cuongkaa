import os

from fastapi import FastAPI
from pydantic import BaseModel

ROLE = os.getenv("MOCK_ROLE", "core")
SERVICE_NAME = f"mock-{ROLE}"
SERVICE_VERSION = "1.0.0"

app = FastAPI(title=SERVICE_NAME, version=SERVICE_VERSION)


class AccessRequest(BaseModel):
    event_id: str
    gate_id: str
    credential_id: str
    direction: str
    timestamp: str
    metadata: dict = {}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME, "version": SERVICE_VERSION}


@app.post("/api/v1/access-events")
def decide_access(payload: AccessRequest) -> dict:
    allowed = not payload.credential_id.upper().startswith("BLOCKED")
    return {
        "decision": "ALLOW" if allowed else "DENY",
        "reason": "Credential is active" if allowed else "Credential is blocked",
        "subject_id": f"USER-{payload.credential_id}",
    }


@app.post("/api/v1/events", status_code=202)
def accept_analytics_event(payload: dict) -> dict:
    return {"accepted": True, "event_id": payload.get("event_id")}
