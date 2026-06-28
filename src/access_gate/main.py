import csv
import json
import logging
import os
import ssl
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx
from paho.mqtt import client as mqtt
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
ANALYTICS_AUTH_TOKEN = os.getenv("ANALYTICS_AUTH_TOKEN", AUTH_TOKEN)
CORE_AUTH_TOKEN = os.getenv("CORE_AUTH_TOKEN", AUTH_TOKEN)
DEPENDENCY_TIMEOUT_SECONDS = float(os.getenv("DEPENDENCY_TIMEOUT_SECONDS", "5"))
DEPENDENCY_RETRIES = int(os.getenv("DEPENDENCY_RETRIES", "1"))
WHITELIST_PATH = os.getenv("WHITELIST_PATH", "Acessgate_uid_whitelist.csv")
MQTT_ENABLED = os.getenv("MQTT_ENABLED", "false").lower() == "true"
MQTT_HOST = os.getenv("MQTT_HOST", "")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
MQTT_TLS = os.getenv("MQTT_TLS", "true").lower() == "true"
MQTT_INPUT_TOPIC = os.getenv("MQTT_INPUT_TOPIC", "smart-campus/raw/access/rfid-uid")
MQTT_OUTPUT_TOPIC = os.getenv("MQTT_OUTPUT_TOPIC", "smart-campus/events/access")

UID_WHITELIST: dict[str, dict[str, str]] = {}
RFID_PROCESSOR: Optional["AccessGateWhitelistProcessor"] = None
MQTT_CLIENT: Optional[mqtt.Client] = None


class Direction(str, Enum):
    entry = "entry"
    exit = "exit"


class RfidDirection(str, Enum):
    entry = "in"
    exit = "out"


class Decision(str, Enum):
    allow = "ALLOW"
    deny = "DENY"


class AccessEventCreate(BaseModel):
    gate_id: str = Field(..., min_length=2, max_length=64)
    credential_id: str = Field(..., min_length=2, max_length=128)
    direction: Direction
    timestamp: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class RawRfidEvent(BaseModel):
    event_id: str
    event_type: str
    source_service: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: datetime
    uid: str
    door_id: str
    location: Optional[str] = None
    direction: RfidDirection


class ProcessedRfidEvent(BaseModel):
    event_id: str
    event_type: str = "access.swipe.processed"
    source_service: str = "team-gate"
    timestamp: datetime
    processed_at: datetime
    raw_event_id: str
    uid: str
    student_id: Optional[str] = None
    full_name: Optional[str] = None
    class_name: Optional[str] = None
    door_id: str
    location: Optional[str] = None
    direction: RfidDirection
    access_result: str
    reason: str


class AccessPolicyCheckRequest(BaseModel):
    request_id: Optional[str] = None
    timestamp: datetime
    uid: str
    door_id: str
    location: Optional[str] = None
    direction: RfidDirection


class AccessPolicyCheckResponse(BaseModel):
    request_id: str
    timestamp: datetime
    processed_at: datetime
    uid: str
    student_id: Optional[str] = None
    full_name: Optional[str] = None
    class_name: Optional[str] = None
    door_id: str
    location: Optional[str] = None
    direction: RfidDirection
    access_result: str
    reason: str


class StoredRfidSwipe(ProcessedRfidEvent):
    ingress: str
    created_at: datetime


class AccessGateWhitelistProcessor:
    def __init__(self, whitelist: dict[str, dict[str, str]]) -> None:
        self.whitelist = whitelist

    @property
    def whitelist_count(self) -> int:
        return len(self.whitelist)

    def process(self, raw_event: RawRfidEvent) -> ProcessedRfidEvent:
        uid = raw_event.uid.strip().upper()
        student = self.whitelist.get(uid)
        processed_at = datetime.now(timezone.utc)

        if student:
            return ProcessedRfidEvent(
                event_id=f"access-event-{uuid.uuid4().hex[:8]}",
                timestamp=raw_event.timestamp,
                processed_at=processed_at,
                raw_event_id=raw_event.event_id,
                uid=uid,
                student_id=student["student_id"],
                full_name=student["full_name"],
                class_name=student["class_name"],
                door_id=raw_event.door_id,
                location=raw_event.location,
                direction=raw_event.direction,
                access_result="granted",
                reason="uid_matched",
            )

        return ProcessedRfidEvent(
            event_id=f"access-event-{uuid.uuid4().hex[:8]}",
            timestamp=raw_event.timestamp,
            processed_at=processed_at,
            raw_event_id=raw_event.event_id,
            uid=uid,
            door_id=raw_event.door_id,
            location=raw_event.location,
            direction=raw_event.direction,
            access_result="denied",
            reason="uid_not_found",
        )


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
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS rfid_swipe_events (
                        event_id VARCHAR(64) PRIMARY KEY,
                        raw_event_id VARCHAR(128) NOT NULL,
                        ingress VARCHAR(32) NOT NULL,
                        event_timestamp TIMESTAMPTZ NOT NULL,
                        processed_at TIMESTAMPTZ NOT NULL,
                        uid VARCHAR(128) NOT NULL,
                        student_id VARCHAR(64),
                        full_name VARCHAR(255),
                        class_name VARCHAR(128),
                        door_id VARCHAR(64) NOT NULL,
                        location VARCHAR(255),
                        direction VARCHAR(16) NOT NULL,
                        access_result VARCHAR(16) NOT NULL,
                        reason VARCHAR(64) NOT NULL,
                        raw_payload JSONB NOT NULL,
                        processed_payload JSONB NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_rfid_swipe_events_created_at
                    ON rfid_swipe_events (created_at DESC)
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


def load_uid_whitelist() -> dict[str, dict[str, str]]:
    whitelist: dict[str, dict[str, str]] = {}
    if not os.path.exists(WHITELIST_PATH):
        LOGGER.warning("UID whitelist file not found: %s", WHITELIST_PATH)
        return whitelist

    with open(WHITELIST_PATH, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            uid = row.get("uid", "").strip().upper()
            if uid:
                whitelist[uid] = {
                    "student_id": row.get("student_id", "").strip(),
                    "full_name": row.get("full_name", "").strip(),
                    "class_name": row.get("class_name", "").strip(),
                }

    LOGGER.info("Loaded %s whitelisted RFID UIDs", len(whitelist))
    return whitelist


def process_raw_rfid_event(raw_event: RawRfidEvent) -> ProcessedRfidEvent:
    if RFID_PROCESSOR is None:
        raise RuntimeError("RFID processor is not initialized")
    return RFID_PROCESSOR.process(raw_event)


def store_rfid_swipe(
    raw_event: RawRfidEvent,
    processed_event: ProcessedRfidEvent,
    ingress: str,
) -> None:
    created_at = datetime.now(timezone.utc)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO rfid_swipe_events (
                event_id, raw_event_id, ingress, event_timestamp, processed_at,
                uid, student_id, full_name, class_name, door_id, location,
                direction, access_result, reason, raw_payload,
                processed_payload, created_at
            ) VALUES (
                %(event_id)s, %(raw_event_id)s, %(ingress)s,
                %(event_timestamp)s, %(processed_at)s, %(uid)s,
                %(student_id)s, %(full_name)s, %(class_name)s, %(door_id)s,
                %(location)s, %(direction)s, %(access_result)s, %(reason)s,
                %(raw_payload)s, %(processed_payload)s, %(created_at)s
            )
            """,
            {
                "event_id": processed_event.event_id,
                "raw_event_id": processed_event.raw_event_id,
                "ingress": ingress,
                "event_timestamp": processed_event.timestamp,
                "processed_at": processed_event.processed_at,
                "uid": processed_event.uid,
                "student_id": processed_event.student_id,
                "full_name": processed_event.full_name,
                "class_name": processed_event.class_name,
                "door_id": processed_event.door_id,
                "location": processed_event.location,
                "direction": processed_event.direction,
                "access_result": processed_event.access_result,
                "reason": processed_event.reason,
                "raw_payload": psycopg.types.json.Jsonb(
                    raw_event.model_dump(mode="json")
                ),
                "processed_payload": psycopg.types.json.Jsonb(
                    processed_event.model_dump(mode="json")
                ),
                "created_at": created_at,
            },
        )
        connection.commit()
    LOGGER.info(
        "Stored RFID swipe %s in database (ingress=%s)",
        processed_event.event_id,
        ingress,
    )


def publish_processed_event(processed_event: ProcessedRfidEvent) -> str:
    if MQTT_CLIENT is None:
        LOGGER.info("MQTT disabled; processed event not published: %s", processed_event.event_id)
        return "disabled"

    payload = build_analytics_mqtt_payload(processed_event)
    result = MQTT_CLIENT.publish(MQTT_OUTPUT_TOPIC, json.dumps(payload), qos=1)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        LOGGER.error("Failed to publish %s to %s: rc=%s", processed_event.event_id, MQTT_OUTPUT_TOPIC, result.rc)
        return "failed"
    else:
        LOGGER.info("Published %s to %s", processed_event.event_id, MQTT_OUTPUT_TOPIC)
        return "published"


def format_mqtt_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_analytics_mqtt_payload(processed_event: ProcessedRfidEvent) -> dict[str, Any]:
    payload = processed_event.model_dump(mode="json")
    payload.update(
        {
            "event_type": "access.log.processed",
            "timestamp": format_mqtt_timestamp(processed_event.timestamp),
            "processed_at": format_mqtt_timestamp(processed_event.processed_at),
            "decision": processed_event.access_result,
            "gate_id": processed_event.door_id,
        }
    )
    return payload


def build_core_access_payload(processed_event: ProcessedRfidEvent) -> dict[str, Any]:
    return {
        "event_id": processed_event.event_id,
        "event_type": processed_event.event_type,
        "source_service": processed_event.source_service,
        "timestamp": processed_event.timestamp.isoformat(),
        "raw_event_id": processed_event.raw_event_id,
        "uid": processed_event.uid,
        "student_id": processed_event.student_id,
        "full_name": processed_event.full_name,
        "class_name": processed_event.class_name,
        "door_id": processed_event.door_id,
        "gate_id": processed_event.door_id,
        "location": processed_event.location,
        "direction": processed_event.direction,
        "access_result": processed_event.access_result,
        "reason": processed_event.reason,
        "actor_type": "student" if processed_event.student_id else "unknown",
    }


def send_processed_event_to_core_sync(processed_event: ProcessedRfidEvent) -> str:
    payload = build_core_access_payload(processed_event)
    headers = {"Authorization": f"Bearer {CORE_AUTH_TOKEN}"}
    try:
        with httpx.Client(timeout=DEPENDENCY_TIMEOUT_SECONDS) as client:
            response = client.post(
                f"{CORE_SERVICE_URL}{CORE_ACCESS_PATH}",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
        LOGGER.info(
            "Sent %s access event %s to Core",
            payload["actor_type"],
            processed_event.event_id,
        )
        return "sent"
    except httpx.HTTPError as exc:
        LOGGER.error("Core delivery failed for %s: %s", processed_event.event_id, exc)
        return "failed"


def handle_mqtt_message(_: mqtt.Client, __: Any, message: mqtt.MQTTMessage) -> None:
    try:
        raw_payload = json.loads(message.payload.decode("utf-8"))
        raw_event = RawRfidEvent.model_validate(raw_payload)
        processed_event = process_raw_rfid_event(raw_event)
        LOGGER.info(
            "RFID %s processed as %s (%s)",
            raw_event.uid,
            processed_event.access_result,
            processed_event.reason,
        )
        store_rfid_swipe(raw_event, processed_event, "mqtt")
        send_processed_event_to_core_sync(processed_event)
        publish_processed_event(processed_event)
    except Exception as exc:
        LOGGER.exception("Failed to process MQTT message from %s: %s", message.topic, exc)


def start_mqtt_client() -> Optional[mqtt.Client]:
    if not MQTT_ENABLED:
        LOGGER.info("MQTT worker is disabled")
        return None
    if not MQTT_HOST:
        LOGGER.warning("MQTT worker is enabled but host is missing")
        return None

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv5)
    if MQTT_USERNAME or MQTT_PASSWORD:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    if MQTT_TLS:
        client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)

    def on_connect(
        client_instance: mqtt.Client,
        _: Any,
        __: Any,
        reason_code: mqtt.ReasonCode,
        ___: Any,
    ) -> None:
        LOGGER.info("MQTT connected with reason code: %s", reason_code)
        client_instance.subscribe(MQTT_INPUT_TOPIC, qos=1)

    client.on_connect = on_connect
    client.on_message = handle_mqtt_message
    client.connect(MQTT_HOST, MQTT_PORT)
    client.loop_start()
    LOGGER.info("MQTT worker started; subscribed topic will be %s", MQTT_INPUT_TOPIC)
    return client


@asynccontextmanager
async def lifespan(_: FastAPI):
    global MQTT_CLIENT, RFID_PROCESSOR, UID_WHITELIST
    initialize_database()
    UID_WHITELIST = load_uid_whitelist()
    RFID_PROCESSOR = AccessGateWhitelistProcessor(UID_WHITELIST)
    MQTT_CLIENT = start_mqtt_client()
    try:
        yield
    finally:
        if MQTT_CLIENT is not None:
            MQTT_CLIENT.loop_stop()
            MQTT_CLIENT.disconnect()
            LOGGER.info("MQTT worker stopped")


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
    analytics_payload = build_analytics_payload(payload, event_id, decision, created_at)
    headers = {"Authorization": f"Bearer {ANALYTICS_AUTH_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=DEPENDENCY_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{ANALYTICS_SERVICE_URL}{ANALYTICS_EVENT_PATH}",
                headers=headers,
                json=analytics_payload,
            )
            response.raise_for_status()
        return "sent"
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.error("Analytics delivery failed for %s: %s", event_id, exc)
        return "failed"


def build_analytics_payload(
    payload: AccessEventCreate,
    event_id: str,
    decision: CoreDecision,
    created_at: datetime,
) -> dict[str, Any]:
    if ANALYTICS_EVENT_PATH == "/readings":
        return {
            "device_id": payload.gate_id,
            "metric": "motion",
            "value": 1 if decision.decision == Decision.allow else 0,
            "unit": "boolean",
            "timestamp": payload.timestamp.isoformat(),
        }

    return {
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
        "mqtt": "enabled" if MQTT_CLIENT is not None else "disabled",
        "whitelist_count": str(RFID_PROCESSOR.whitelist_count if RFID_PROCESSOR else 0),
    }


@app.post(
    "/api/v1/rfid/raw",
    response_model=ProcessedRfidEvent,
    status_code=202,
    dependencies=[Depends(verify_token)],
)
def process_rfid_raw(payload: RawRfidEvent) -> ProcessedRfidEvent:
    processed_event = process_raw_rfid_event(payload)
    store_rfid_swipe(payload, processed_event, "rest")
    send_processed_event_to_core_sync(processed_event)
    publish_processed_event(processed_event)
    return processed_event


@app.post(
    "/api/v1/access/check",
    response_model=AccessPolicyCheckResponse,
    dependencies=[Depends(verify_token)],
)
def check_access_policy(payload: AccessPolicyCheckRequest) -> AccessPolicyCheckResponse:
    request_id = payload.request_id or f"core-policy-{uuid.uuid4().hex[:8]}"
    raw_event = RawRfidEvent(
        event_id=request_id,
        event_type="access.policy.check.requested",
        source_service="core-business",
        timestamp=payload.timestamp,
        uid=payload.uid,
        door_id=payload.door_id,
        location=payload.location,
        direction=payload.direction,
    )
    processed_event = process_raw_rfid_event(raw_event)
    store_rfid_swipe(raw_event, processed_event, "core_policy")
    LOGGER.info(
        "Core policy check %s returned %s (%s)",
        request_id,
        processed_event.access_result,
        processed_event.reason,
    )
    return AccessPolicyCheckResponse(
        request_id=request_id,
        timestamp=processed_event.timestamp,
        processed_at=processed_event.processed_at,
        uid=processed_event.uid,
        student_id=processed_event.student_id,
        full_name=processed_event.full_name,
        class_name=processed_event.class_name,
        door_id=processed_event.door_id,
        location=processed_event.location,
        direction=processed_event.direction,
        access_result=processed_event.access_result,
        reason=processed_event.reason,
    )


@app.get(
    "/api/v1/rfid/swipes/latest",
    response_model=dict[str, list[StoredRfidSwipe]],
    dependencies=[Depends(verify_token)],
)
def latest_rfid_swipes(
    access_result: Optional[str] = Query(default=None, pattern="^(granted|denied)$"),
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, list[dict[str, Any]]]:
    sql = """
        SELECT processed_payload, ingress, created_at
        FROM rfid_swipe_events
    """
    params: dict[str, Any] = {"limit": limit}
    if access_result:
        sql += " WHERE access_result = %(access_result)s"
        params["access_result"] = access_result
    sql += " ORDER BY created_at DESC LIMIT %(limit)s"

    with get_connection() as connection:
        rows = connection.execute(sql, params).fetchall()

    items = []
    for row in rows:
        item = dict(row["processed_payload"])
        item["ingress"] = row["ingress"]
        item["created_at"] = row["created_at"]
        items.append(item)
    return {"items": items}


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
