import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("access-gate")

SERVICE_NAME = os.getenv("SERVICE_NAME", "access-gate")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "local-dev-token")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://gate:gatepass@db:5432/gatedb",
)
CORE_SERVICE_URL = os.getenv("CORE_SERVICE_URL", "http://mock-core:8001").rstrip("/")
CORE_ACCESS_PATH = os.getenv("CORE_ACCESS_PATH", "/api/v1/access-events")
ANALYTICS_SERVICE_URL = os.getenv(
    "ANALYTICS_SERVICE_URL", "http://mock-analytics:8002"
).rstrip("/")
ANALYTICS_EVENT_PATH = os.getenv("ANALYTICS_EVENT_PATH", "/api/v1/events")
DEPENDENCY_TIMEOUT_SECONDS = float(os.getenv("DEPENDENCY_TIMEOUT_SECONDS", "5"))
DEPENDENCY_RETRIES = int(os.getenv("DEPENDENCY_RETRIES", "1"))


class Direction(str, Enum):
    entry = "entry"
    exit = "exit"


class Decision(str, Enum):
    allow = "ALLOW"
    deny = "DENY"


class AccessEventCreate(BaseModel):
    gate_id: str = Field(..., min_length=2, max_length=64)
    credential_id: str = Field(..., min_length=2, max_length=128)
    direction: Direction
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoreDecision(BaseModel):
    decision: Decision
    reason: str
    subject_id: Optional[str] = None


class AccessEvent(BaseModel):
    event_id: str
    gate_id: str
    credential_id: str
    direction: Direction
    timestamp: datetime
    decision: Decision
    reason: str
    subject_id: Optional[str] = None
    analytics_status: str
    created_at: datetime


class AccessEventResult(BaseModel):
    event_id: str
    decision: Decision
    reason: str
    subject_id: Optional[str] = None
    analytics_status: str
    created_at: datetime


def problem(
    status_code: int,
    title: str,
    detail: str,
    instance: str,
    problem_type: str = "about:blank",
) -> dict[str, Any]:
    return {
        "type": problem_type,
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": instance,
    }


def get_connection() -> psycopg.Connection:
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def initialize_database() -> None:
    last_error: Optional[Exception] = None
    for attempt in range(1, 11):
        try:
            with get_connection() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS access_events (
                        event_id VARCHAR(64) PRIMARY KEY,
                        gate_id VARCHAR(64) NOT NULL,
                        credential_id VARCHAR(128) NOT NULL,
                        direction VARCHAR(16) NOT NULL,
                        event_timestamp TIMESTAMPTZ NOT NULL,
                        decision VARCHAR(16) NOT NULL,
                        reason TEXT NOT NULL,
                        subject_id VARCHAR(128),
                        analytics_status VARCHAR(32) NOT NULL,
                        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                connection.commit()
            LOGGER.info("Database schema is ready")
            return
        except psycopg.Error as exc:
            last_error = exc
            LOGGER.warning("Database unavailable (attempt %s/10): %s", attempt, exc)
            time.sleep(2)
    raise RuntimeError("Database did not become ready") from last_error


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="FIT4110 Access Gate Service",
    version=SERVICE_VERSION,
    description="Access Gate service integrated with Business Core and Analytics.",
    lifespan=lifespan,
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    content = (
        exc.detail
        if isinstance(exc.detail, dict)
        else problem(exc.status_code, "Request failed", str(exc.detail), request.url.path)
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        media_type="application/problem+json",
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    first_error = exc.errors()[0] if exc.errors() else {}
    location = ".".join(str(value) for value in first_error.get("loc", []))
    detail = first_error.get("msg", "Request validation error")
    if location:
        detail = f"{location}: {detail}"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem(
            422,
            "Validation error",
            detail,
            request.url.path,
            "https://smart-campus.local/problems/validation-error",
        ),
        media_type="application/problem+json",
    )


def verify_token(authorization: Optional[str] = Header(default=None)) -> None:
    if authorization != f"Bearer {AUTH_TOKEN}":
        raise HTTPException(
            status_code=401,
            detail=problem(
                401,
                "Unauthorized",
                "Missing or invalid bearer token",
                "/api/v1/access-events",
                "https://smart-campus.local/problems/unauthorized",
            ),
        )


async def request_core(payload: AccessEventCreate, event_id: str) -> CoreDecision:
    request_payload = {
        "event_id": event_id,
        "gate_id": payload.gate_id,
        "credential_id": payload.credential_id,
        "direction": payload.direction.value,
        "timestamp": payload.timestamp.isoformat(),
        "metadata": payload.metadata,
    }
    last_error = "Business Core is unavailable"
    for attempt in range(DEPENDENCY_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=DEPENDENCY_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{CORE_SERVICE_URL}{CORE_ACCESS_PATH}", json=request_payload
                )
                response.raise_for_status()
                return CoreDecision.model_validate(response.json())
        except httpx.TimeoutException:
            last_error = "Business Core timed out"
        except httpx.HTTPStatusError as exc:
            last_error = f"Business Core returned HTTP {exc.response.status_code}"
        except (httpx.RequestError, ValueError) as exc:
            last_error = f"Cannot reach Business Core: {exc}"
        LOGGER.warning(
            "Core request failed (attempt %s/%s): %s",
            attempt + 1,
            DEPENDENCY_RETRIES + 1,
            last_error,
        )
    raise HTTPException(
        status_code=503,
        detail=problem(
            503,
            "Business Core unavailable",
            f"{last_error}; access denied by fail-closed policy",
            "/api/v1/access-events",
            "https://smart-campus.local/problems/dependency-unavailable",
        ),
    )


async def send_analytics(
    payload: AccessEventCreate,
    event_id: str,
    decision: CoreDecision,
    created_at: datetime,
) -> str:
    analytics_payload = {
        "event_id": event_id,
        "event_type": "access-gate",
        "gate_id": payload.gate_id,
        "credential_id": payload.credential_id,
        "direction": payload.direction.value,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "subject_id": decision.subject_id,
        "timestamp": payload.timestamp.isoformat(),
        "created_at": created_at.isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=DEPENDENCY_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{ANALYTICS_SERVICE_URL}{ANALYTICS_EVENT_PATH}",
                json=analytics_payload,
            )
            response.raise_for_status()
        return "sent"
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.error("Analytics delivery failed for %s: %s", event_id, exc)
        return "failed"


def store_event(
    payload: AccessEventCreate,
    event_id: str,
    decision: CoreDecision,
    analytics_status: str,
    created_at: datetime,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO access_events (
                event_id, gate_id, credential_id, direction, event_timestamp,
                decision, reason, subject_id, analytics_status, metadata, created_at
            ) VALUES (
                %(event_id)s, %(gate_id)s, %(credential_id)s, %(direction)s,
                %(event_timestamp)s, %(decision)s, %(reason)s, %(subject_id)s,
                %(analytics_status)s, %(metadata)s, %(created_at)s
            )
            """,
            {
                "event_id": event_id,
                "gate_id": payload.gate_id,
                "credential_id": payload.credential_id,
                "direction": payload.direction.value,
                "event_timestamp": payload.timestamp,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "subject_id": decision.subject_id,
                "analytics_status": analytics_status,
                "metadata": psycopg.types.json.Jsonb(payload.metadata),
                "created_at": created_at,
            },
        )
        connection.commit()


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        database = "ready"
    except psycopg.Error:
        database = "unavailable"
    return {
        "status": "ok" if database == "ready" else "degraded",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "database": database,
    }


@app.post(
    "/api/v1/access-events",
    response_model=AccessEventResult,
    status_code=201,
    dependencies=[Depends(verify_token)],
)
async def create_access_event(payload: AccessEventCreate) -> AccessEventResult:
    event_id = f"GATE-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
    created_at = datetime.now(timezone.utc)
    decision = await request_core(payload, event_id)
    analytics_status = await send_analytics(payload, event_id, decision, created_at)
    store_event(payload, event_id, decision, analytics_status, created_at)
    return AccessEventResult(
        event_id=event_id,
        decision=decision.decision,
        reason=decision.reason,
        subject_id=decision.subject_id,
        analytics_status=analytics_status,
        created_at=created_at,
    )


@app.get(
    "/api/v1/access-events/latest",
    response_model=dict[str, list[AccessEvent]],
    dependencies=[Depends(verify_token)],
)
def latest_access_events(
    gate_id: Optional[str] = Query(default=None),
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, list[dict[str, Any]]]:
    sql = """
        SELECT event_id, gate_id, credential_id, direction,
               event_timestamp AS timestamp, decision, reason, subject_id,
               analytics_status, created_at
        FROM access_events
    """
    params: dict[str, Any] = {"limit": limit}
    if gate_id:
        sql += " WHERE gate_id = %(gate_id)s"
        params["gate_id"] = gate_id
    sql += " ORDER BY created_at DESC LIMIT %(limit)s"
    with get_connection() as connection:
        rows = connection.execute(sql, params).fetchall()
    return {"items": rows}


@app.get(
    "/api/v1/access-events/{event_id}",
    response_model=AccessEvent,
    dependencies=[Depends(verify_token)],
)
def get_access_event(event_id: str) -> dict[str, Any]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT event_id, gate_id, credential_id, direction,
                   event_timestamp AS timestamp, decision, reason, subject_id,
                   analytics_status, created_at
            FROM access_events WHERE event_id = %s
            """,
            (event_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=problem(
                404,
                "Not Found",
                f"Access event {event_id} does not exist",
                f"/api/v1/access-events/{event_id}",
                "https://smart-campus.local/problems/not-found",
            ),
        )
    return row
