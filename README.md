# FIT4110 Access Gate Service

Access Gate supports two integration flows:

- REST access decision flow: receive a credential event, ask Business Core for
  an `ALLOW` or `DENY` decision, store the result in PostgreSQL, and send a
  metric to Analytics.
- MQTT RFID flow: subscribe raw RFID UID messages from HiveMQ, compare each UID
  with `Acessgate_uid_whitelist.csv`, store every swipe in PostgreSQL, and
  publish a processed access event.
- Core policy flow: let Core Business call Access Gate synchronously to check
  whether one UID is granted or denied.

## Architecture

```text
Gate device/Postman -> Access Gate API -> Business Core
                              |
                              +-> PostgreSQL
                              |
                              +-> Analytics
```

The local Compose stack includes mock Core and Analytics services so the
complete flow can be tested before the in-class multi-laptop integration.

## Main endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service and database readiness |
| POST | `/api/v1/access-events` | Request a Core decision and record an event |
| POST | `/api/v1/rfid/raw` | Test/process one raw RFID UID payload |
| POST | `/api/v1/access/check` | Let Core check an RFID UID in realtime |
| GET | `/api/v1/rfid/swipes/latest` | Query stored RFID swipe audit records |
| GET | `/api/v1/access-events/latest` | Query recent events |
| GET | `/api/v1/access-events/{event_id}` | Query one event |

Protected endpoints require:

```text
Authorization: Bearer local-dev-token
```

## Quick start

```powershell
Copy-Item .env.example .env
docker compose up -d --build --wait
docker compose ps
curl.exe http://localhost:8000/health
npm install
npm run test:compose
```

OpenAPI contract: `contracts/access-gate.openapi.yaml`.

## MQTT RFID flow

The service loads valid UIDs from `Acessgate_uid_whitelist.csv`. For each raw
RFID payload, it returns/publishes:

- `access_result: granted`, `reason: uid_matched` when the UID exists.
- `access_result: denied`, `reason: uid_not_found` when the UID is unknown.
- MQTT payload also includes `decision: granted|denied` for the Analytics
  dashboard contract.

Analytics MQTT contract:

```env
MQTT_HOST=26.109.160.213
MQTT_PORT=1883
MQTT_TLS=false
MQTT_OUTPUT_TOPIC=smart-campus/events/access
```

Published JSON example:

```json
{
  "event_id": "access-event-12345678",
  "event_type": "access.log.processed",
  "timestamp": "2026-06-27T01:30:00Z",
  "location": "Main Gate",
  "uid": "04:A1:B2:C3:D4:03",
  "decision": "granted",
  "access_result": "granted",
  "reason": "uid_matched",
  "door_id": "gate-a",
  "gate_id": "gate-a",
  "direction": "in",
  "student_id": "SV003",
  "full_name": "Le Minh Cuong",
  "class_name": "CNTT"
}
```

Analytics can verify messages with:

```powershell
docker run --rm eclipse-mosquitto:2 mosquitto_sub -h 26.109.160.213 -p 1883 -t smart-campus/events/access -v
```

Local REST smoke test for the same logic:

```powershell
$headers = @{ Authorization = "Bearer local-dev-token" }
$body = @{
  event_id = "raw-rfid-abc123"
  event_type = "rfid.uid.scanned"
  source_service = "pi-rfid-simulator"
  device_id = "rfid-reader-gate-01"
  timestamp = "2026-06-07T14:30:10+07:00"
  uid = "04:A1:B2:C3:D4:03"
  door_id = "gate-a"
  location = "Main Gate A"
  direction = "in"
} | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "http://localhost:8000/api/v1/rfid/raw" -Headers $headers -ContentType "application/json" -Body $body
```

Core Business can check access policy synchronously:

```powershell
$headers = @{ Authorization = "Bearer local-dev-token" }
$body = @{
  request_id = "core-policy-001"
  timestamp = "2026-06-20T09:30:00+07:00"
  uid = "04:A1:B2:C3:D4:03"
  door_id = "gate-a"
  location = "Main Gate A"
  direction = "in"
} | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "http://localhost:8000/api/v1/access/check" -Headers $headers -ContentType "application/json" -Body $body
```

Verify that MQTT, REST, and Core policy swipes were stored:

```powershell
Invoke-RestMethod -Method GET -Uri "http://localhost:8000/api/v1/rfid/swipes/latest?limit=10" -Headers $headers
```

To connect to the Analytics Radmin Mosquitto broker, set this in `.env`:

```env
MQTT_ENABLED=true
MQTT_HOST=26.109.160.213
MQTT_PORT=1883
MQTT_TLS=false
MQTT_USERNAME=
MQTT_PASSWORD=
MQTT_INPUT_TOPIC=smart-campus/raw/access/rfid-uid
MQTT_OUTPUT_TOPIC=smart-campus/events/access
```

## Buoi 6 partner integration

Containers on this laptop use Docker service names such as `db`. Services on
another laptop must be called through that laptop's hotspot IP address.

Update `.env` at the start of class:

```env
CORE_SERVICE_URL=http://192.168.43.56:8000
ANALYTICS_SERVICE_URL=http://192.168.43.57:8000
```

Then rebuild/recreate the API:

```powershell
docker compose up -d --build --force-recreate api
```

The partner teams must confirm the configured paths:

```env
CORE_ACCESS_PATH=/api/v1/access-events
ANALYTICS_EVENT_PATH=/api/v1/events
```

The API uses a 5-second timeout by default. Business Core failure returns HTTP
503 and denies access by fail-closed policy. Analytics failure is logged and
returned as `analytics_status: failed` without changing Core's decision.
