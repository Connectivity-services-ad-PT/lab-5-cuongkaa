# Run the Access Gate stack

## Requirements

- Docker Desktop with Compose v2
- Node.js 20 or newer for Newman

## Start

```powershell
Copy-Item .env.example .env
docker compose config --quiet
docker compose up -d --build --wait
docker compose ps
```

Expected containers:

```text
fit4110-access-gate
fit4110-gate-db
fit4110-mock-core
fit4110-mock-analytics
```

## Smoke tests

```powershell
curl.exe http://localhost:8000/health

curl.exe -X POST http://localhost:8000/api/v1/access-events `
  -H "Authorization: Bearer local-dev-token" `
  -H "Content-Type: application/json" `
  -d '{"gate_id":"GATE-A01","credential_id":"CARD-001","direction":"entry","timestamp":"2026-06-10T09:30:00+07:00"}'
```

Credential IDs beginning with `BLOCKED` are denied by the local Core mock.

RFID whitelist logic can be tested without HiveMQ:

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

Expected result: `access_result` is `granted` and `student_id` is `SV003`.

To use HiveMQ, set `MQTT_ENABLED=true` and fill `MQTT_USERNAME` /
`MQTT_PASSWORD` in `.env`. Do not commit the real password.

## Newman reports

```powershell
npm install
npm run test:compose
```

Reports are written to:

```text
reports/newman-lab05-compose.xml
reports/newman-lab05-compose.html
```

## Connect to real partner laptops

Find the partner laptop IPv4 address on the shared hotspot and edit `.env`:

```env
CORE_SERVICE_URL=http://<core-ip>:8000
ANALYTICS_SERVICE_URL=http://<analytics-ip>:8000
```

Do not change `DATABASE_URL`; PostgreSQL remains on the local Docker network.

Verify connectivity before starting the demo:

```powershell
curl.exe http://<core-ip>:8000/health
curl.exe http://<analytics-ip>:8000/health
docker compose up -d --build --force-recreate api
```

Ensure Windows Firewall allows inbound TCP port 8000 for the Access Gate API.

## Logs and cleanup

```powershell
docker compose logs --no-color > reports/logs-compose.txt
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove stored
database data.
