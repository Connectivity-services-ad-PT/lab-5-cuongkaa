import os

from fastapi import FastAPI
from typing import Optional

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


class ProcessedAccessEvent(BaseModel):
    event_id: str
    event_type: str
    uid: str
    door_id: str
    direction: str
    access_result: str
    reason: str
    actor_type: str
    student_id: Optional[str] = None
    full_name: Optional[str] = None
    class_name: Optional[str] = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME, "version": SERVICE_VERSION}


@app.post("/api/v1/access-events")
def decide_access(payload: AccessRequest | ProcessedAccessEvent) -> dict:
    if isinstance(payload, ProcessedAccessEvent):
        return {
            "accepted": True,
            "event_id": payload.event_id,
            "actor_type": payload.actor_type,
            "access_result": payload.access_result,
        }

    allowed = not payload.credential_id.upper().startswith("BLOCKED")
    return {
        "decision": "ALLOW" if allowed else "DENY",
        "reason": "Credential is active" if allowed else "Credential is blocked",
        "subject_id": f"USER-{payload.credential_id}",
    }


@app.post("/api/v1/events", status_code=202)
def accept_analytics_event(payload: dict) -> dict:
    return {"accepted": True, "event_id": payload.get("event_id")}


@app.post("/readings", status_code=201)
def accept_iot_reading(payload: dict) -> dict:
    return {
        "reading_id": f"MOCK-{payload.get('device_id', 'UNKNOWN')}",
        "device_id": payload.get("device_id"),
        "metric": payload.get("metric"),
        "accepted": True,
        "created_at": payload.get("timestamp"),
    }
