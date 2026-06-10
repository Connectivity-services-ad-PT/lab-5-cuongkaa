# Access Gate Readiness Checklist

- [x] **Database ready:** PostgreSQL has a `pg_isready` healthcheck and `/health` verifies the connection.
- [x] **Business Core ready:** local mock is healthy; the real URL is configured with `CORE_SERVICE_URL`.
- [x] **Analytics ready:** local mock accepts events; the real URL is configured with `ANALYTICS_SERVICE_URL`.
- [x] **API ready:** health and Access Gate endpoints use bearer authentication where required.
- [x] **Timeout handling:** Core uses a configurable timeout/retry and fails closed with HTTP 503.
- [x] **Network and ports:** the API is published on port 8000 and binds to `0.0.0.0`.
- [x] **Environment variables:** `.env.example` has local-safe values and no fixed partner IPs.
- [x] **Image tag:** the API uses `fit4110/access-gate:v1.0.0-team-gate`.
- [x] **Automated tests:** Newman covers health, auth, ALLOW, DENY, validation and queries.

Before the in-class integration:

- [ ] Replace mock URLs in `.env` with partner laptop IP addresses.
- [ ] Test both partner `/health` endpoints through the shared hotspot.
- [x] Save local Compose, health, Newman and timeout evidence in `reports/`.
- [ ] Push the final image tag to the selected registry.
