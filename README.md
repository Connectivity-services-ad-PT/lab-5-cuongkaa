# FIT4110 Access Gate Service

Access Gate receives card/credential events, asks Business Core for an
`ALLOW` or `DENY` decision, stores the result in PostgreSQL, and sends an
event to Analytics.

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
