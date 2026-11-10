# NyensungAI development status — 8 November 2026

## Implemented in this update
- Protected the Windows endpoint ingestion boundary with a dedicated `X-Agent-Key` header and constant-time comparison.
- Backend ingestion fails closed with HTTP 503 until `AGENT_API_KEY` is configured; missing/incorrect agent keys receive HTTP 401.
- Updated the Windows endpoint agent to load its private `.env` file and send the agent key. It refuses to send telemetry if the key is missing.
- Added an authenticated WebSocket endpoint at `/api/security-events/ws`. It validates the JWT, active user, and token revocation state before accepting a client.
- Added a single-process event fan-out service and publish newly persisted endpoint events to connected SOC clients.
- Threat Monitoring now displays live-stream connection state, consumes pushed events, and retains periodic polling as a fallback.
- Added backend and endpoint-agent `.env.example` templates and setup instructions.

## Validation performed in this environment
- Python source syntax compilation (`backend/app` and `endpoint_agent`): **passed**.
- TypeScript/Vite production build: **blocked in this Linux review environment** because the uploaded `node_modules` contains Windows-only TypeScript/Vite native packages (`vite: Permission denied`; TypeScript could not resolve its Linux native package). Run `npm ci` then `npm run build` on Windows.
- Backend application import/integration test: **blocked** because `python-jose` is not installed in this review runtime. Dependencies are declared in `backend/requirements.txt`; install them in the project venv and rerun.
- Live Windows Security Event Log collection: requires Windows and a local administrator/elevated test session; not executable in this Linux environment.
- Live Ollama investigation: requires the user's local Ollama service and model; not executable here.

## Important architecture limits
- WebSocket fan-out is in-memory and supports one backend process. Multi-worker deployment requires Redis pub/sub or another shared broker.
- Endpoint agent currently collects the Windows Security authentication event IDs already supported by the project (4624 and 4625). It is not yet a full EDR sensor.
- Network packet/flow monitoring has not yet been implemented. The platform must not claim to detect network attacks without corresponding telemetry.
- AI investigation remains an analyst-assistance layer; deterministic detections and evidence collection must remain functional when Ollama is offline.

## Before deployment
- Rotate `SECRET_KEY`, any previously exposed keys, and administrator password.
- Set a unique `AGENT_API_KEY` in `backend/.env` and the matching `NYENSUNG_AGENT_API_KEY` in `endpoint_agent/.env`.
- Use HTTPS/WSS, restrict CORS, configure backups, and review roles and API access before exposing the service beyond localhost.
- Never include `.env`, database files with real telemetry, or endpoint checkpoint files in source-control or public ZIP releases.

## Development phase 3 — passive network telemetry
- Added a passive Windows TCP socket observer using `psutil`; it emits normalized connection observations for newly established TCP sockets and suppresses repeat observations while a socket remains active.
- Added a backend multi-port heuristic: >=8 distinct local TCP ports associated with one remote IP in a 60-second window produces a medium-severity `NETWORK_PORT_SCAN_SUSPECTED` event.
- The alert is explicitly an indicator, not proof. Windows socket enumeration does not reliably expose connection direction; outbound ephemeral connections can resemble inbound multi-port activity. Direction-aware packet/flow telemetry is still required for higher-confidence port-scan detection.
- Added unit tests for IP filtering, event normalization, protocol/state filtering, and duplicate suppression.
- No active scanning, packet injection, payload capture, or firewall modification was introduced.

## Phase 3 verification results
- `python -m compileall -q backend/app endpoint_agent`: **passed**.
- `python -m pytest endpoint_agent/tests -q`: **3 passed**.
- Backend network-detection service exercised against an in-memory SQLite database: **passed** (threshold alert created at eight unique ports; duplicate alert suppressed on repeat).
- Full FastAPI application import/integration remains **blocked in this review runtime** because `python-jose` is declared in backend requirements but is not installed here, and package installation is unavailable in this environment. Run the backend requirements install and API tests on the Windows development machine.
- Live Windows socket enumeration remains **not run** here; it requires Windows and may require an elevated terminal.

## Development phase 4 — application and authentication abuse indicators
- Added `credential_abuse_detection.py`: detects sustained failed authentication attempts across multiple accounts, requiring at least 12 failures in 10 minutes, at least 3 distinct accounts, and at least 3 accounts with 4+ failures each. It emits `CREDENTIAL_ABUSE_PATTERN` (HIGH, risk 78), deduplicated per source/window.
- This is deliberately named a credential-abuse pattern, not confirmed credential stuffing. The platform does not collect passwords and cannot prove stolen credential-pair reuse from authentication failures alone.
- Added `web_attack_detection.py` for explicit `HTTP_REQUEST_OBSERVED`, `WEB_REQUEST_OBSERVED`, and `WEB_ACCESS_LOG` telemetry only. It emits SQL injection, XSS, and path traversal indicators after URL decoding. Arbitrary system/security event descriptions are not inspected.
- Web alerts avoid copying raw request payloads into alert descriptions, are deduplicated by source and five-minute window, and are published to connected WebSocket clients.
- Newly generated high/critical indicators are included in the existing incident-creation query. Detection is advisory only; no request blocking, firewall changes, or payload execution is performed.
- Added five backend unit tests covering explicit telemetry gating, SQLi, XSS deduplication, path traversal, multi-account credential abuse, and single-account non-trigger behavior.

## Phase 4 verification results
- `SECRET_KEY=test-only-not-for-deployment PYTHONPATH=. pytest -q tests/test_phase4_detections.py`: **5 passed** using an in-memory SQLite database.
- Python syntax compilation for backend application and tests: **passed**.
- Full FastAPI route integration remains **not run** because `python-jose` is not installed in this review runtime. Install the declared backend requirements in the Windows virtual environment and run the documented local checks.
- Live HTTP application telemetry is **not yet wired to a real web server/proxy collector**. The detection engine accepts normalized events from a future authorized application/log adapter; it does not inspect browser traffic or arbitrary network packets.
- No claim is made that SQLi/XSS signatures prove exploitation. Validate with application logs, response codes, WAF evidence, and controlled lab requests.

## Development phase 5 — incident investigation timeline and evidence correlation
- Added authenticated `GET /api/incidents/{incident_id}/timeline?window_minutes=30` endpoint.
- Timeline includes the incident's primary security event, exact-metadata correlated events, analyst notes, and response actions in timestamp order.
- Correlation is bounded to +/- the selected window (1–240 minutes) around the primary event and uses exact source IP, username, and/or request ID matches. Null identifiers are never used as correlation keys.
- Added a risk summary with event count, maximum and average event risk score, and severity counts. Scores are clamped to 0–100 for aggregation only; original event records are not modified.
- Response explicitly states that metadata correlation is not proof of a common attacker or cause. At most 200 related events are returned and truncation is indicated.
- No schema migration is required; the endpoint uses existing incident, event, note, and action tables.

### Phase 5 verification
- `SECRET_KEY=test-only-not-for-deployment PYTHONPATH=. pytest -q tests`: **8 passed** (5 Phase 4 tests + 3 Phase 5 tests).
- `python -m compileall -q app tests`: **passed**.
- Tests use isolated in-memory SQLite and synthetic evidence only.
- Full authenticated FastAPI HTTP integration, frontend display integration, Windows endpoint operation, and Ollama operation remain to be verified on the Windows development machine.

## Phase 6 — Analyst investigation experience (2026-11-08)

### Implemented
- Connected the existing authenticated incident timeline endpoint to the React Incident Response detail view.
- Added an evidence summary showing event count, maximum and average risk score, related-event count, severity distribution, and correlation window.
- Added a chronological activity timeline for security events, analyst notes, and response actions.
- Displayed correlation keys and the backend's explicit limitation that metadata correlation is not proof of common cause or attacker identity.
- Added loading, error, and empty states for timeline retrieval.
- Kept AI analysis advisory-only and preserved existing incident lifecycle, notes, and response-action workflows.

### Verification
- Backend tests: 8 passed when run with a temporary test-only `SECRET_KEY` environment variable.
- Python syntax compilation: passed for backend and endpoint-agent Python files.
- ZIP integrity: verified after packaging.
- Frontend TypeScript/Vite build: not verified. The frontend dependencies were not present in the archive; `npm ci` did not complete in the review environment, and TypeScript reported missing `vite/client` and `node` type packages. Run `npm ci` and `npm run build` on the Windows development machine.
- Live browser, authenticated API, WebSocket, Windows host telemetry, and Ollama end-to-end tests remain pending.

### Notes
- The timeline API existed in the previous phase and remains protected by `get_current_user`; this phase integrates it into the analyst UI rather than duplicating backend functionality.
- No automatic blocking, firewall modification, or destructive response action was added.

## Phase 7 — Analyst assignment and response targets

- Added analyst assignment editing to incident management using the existing `assigned_to` field.
- Assignment changes are recorded as `ANALYST_ASSIGNED` entries in the incident action history.
- Added authenticated `GET /api/incidents/sla/summary` with priority-based operational target estimates (P1 60m, P2 4h, P3 24h, P4 72h).
- Added response-target summary and per-incident status indicators to the incident dashboard.
- Cleaned an accidental duplicate router implementation in `app/routers/incidents.py`; retained the complete implementation with timeline support.
- SLA values are policy defaults, not contractual guarantees. They are calculated from incident creation time and current priority; configure them for the organisation before production use.
- Automated tests added for on-track, breached, completed and unknown-priority SLA behavior.

### Phase 7 verification

- Backend + endpoint-agent automated tests: **15 passed** in the available Linux test environment.
- Python syntax compilation: **passed**.
- Frontend production build: **not verified**; `npm ci` did not complete before the environment timeout, so TypeScript/Vite compilation was not claimed.
- Live Windows Event Log/network collection, live WebSocket, and local Ollama integration remain deployment-machine verification tasks.

## Phase 8 — API access-control hardening (2026-11-08)

### Implemented
- Protected the security-event dashboard statistics and 24-hour activity endpoints with the existing JWT-backed `get_current_user` dependency.
- Protected security-event list, detail, status-update, and AI-investigation endpoints with the same authenticated-user dependency. Previously these analyst-facing routes could expose or modify security telemetry without an access token.
- Kept endpoint-agent ingestion on its separate machine-to-machine `X-Agent-Key` boundary; comparison uses `hmac.compare_digest` and ingestion fails closed when no backend agent key is configured.
- Updated frontend dashboard statistics and activity requests to send the session's bearer token. The existing charts and monitoring pages reuse the same token helper.
- Made the AI investigation frontend service require a token and fail locally with a session-expired message instead of sending an anonymous request.
- Added Phase 8 regression tests to guard analyst-route authentication and agent-key enforcement.

### Phase 8 verification
- `SECRET_KEY=test-only-not-for-deployment PYTHONPATH=. pytest -q tests ../endpoint_agent/tests`: **17 passed**.
- `python -m compileall -q app tests ../endpoint_agent`: **passed**.
- Frontend source-level checks for bearer-token headers: **passed**.
- Full FastAPI HTTP integration remains **not run** because `python-jose` is declared in requirements but is unavailable in this offline review runtime. Install backend requirements on the Windows development machine and test login, unauthenticated 401/403 behavior, authenticated dashboard/event/investigation access, and agent-key rejection/acceptance.
- Frontend production build and browser verification remain **pending** because frontend packages were not installed in this environment. Run `npm ci` and `npm run build` on Windows.
- Live Windows Event Log/network collection and Ollama integration remain **pending**.

### Security notes / known limits
- This phase closes unauthenticated HTTP access to security-event data; it does not implement a complete user/role administration console.
- The WebSocket authenticates the JWT, but currently receives it as a query parameter. Use HTTPS/WSS and ensure reverse-proxy/access logs do not record query strings; a short-lived one-time WebSocket ticket is a future hardening task.
- The WebSocket event hub is process-local. Multi-worker production requires a shared pub/sub broker such as Redis.
- Rotate backend `SECRET_KEY`, endpoint agent key(s), and administrator password before deployment. Never distribute `.env` files or production database files.


## Phase 9 — short-lived WebSocket authentication (2026-11-08)

### Implemented
- Added authenticated `POST /api/auth/ws-ticket`. It requires the existing bearer-token authentication dependency and issues a cryptographically random, single-use WebSocket ticket with a 30-second lifetime.
- Added an in-memory ticket store with expiry cleanup, atomic consume semantics, and binding to the authenticated user ID and source JWT ID. Reuse and expired tickets are rejected.
- Replaced the previous WebSocket `?token=<long-lived-JWT>` URL pattern with `?ticket=<short-lived-one-time-ticket>`. The WebSocket handler checks ticket validity, token revocation state, active user state, and browser Origin against the configured frontend origin plus local development origins.
- Added a lightweight ping/pong heartbeat to the WebSocket connection.
- Updated Threat Monitoring to request a ticket over the authenticated HTTP API before opening WSS/WS. The long-lived bearer token is no longer placed in the WebSocket URL. Periodic API polling remains available as a fallback.
- Added four Phase 9 tests covering single-use behavior, expiry, route parameter/Origin guardrails, and authentication on ticket issuance.

### Phase 9 verification
- `SECRET_KEY=phase9-test-only-not-for-use PYTHONPATH=. pytest -q tests`: **18 passed**. The test key is ephemeral and must never be used outside the test run.
- `python -m compileall -q backend/app endpoint_agent`: **passed**.
- ZIP integrity checked before packaging.
- Full FastAPI application import/HTTP/WebSocket integration remains **blocked** in this runtime because `python-jose` is not installed; the dependency is declared in `backend/requirements.txt`.
- Frontend production build remains **not run** because frontend dependencies are not installed in this environment. Run `npm ci` and `npm run build` on the Windows development machine.
- Live Windows telemetry and Ollama tests remain **pending**.

### Security and deployment limits
- Tickets are in-memory and therefore require a single backend worker. Multi-worker deployment requires a shared, atomic ticket store and shared event pub/sub (for example Redis).
- WebSocket tickets are short-lived and one-use, but still appear in the WebSocket URL for the handshake. Use WSS and configure reverse proxies not to log query strings.
- Origin checks mitigate browser cross-site WebSocket use; they are not a substitute for ticket authentication.
- Before deployment, rotate backend `SECRET_KEY`, endpoint agent keys, and administrator password. Keep `.env` files private.

## Phase 10 — SOC administration, audit trail and investigation search (2026-11-08)

### Implemented
- Added an append-only `audit_logs` table for user login/logout, administrator account-access changes, incident updates, incident notes/actions, and security-event status changes. Audit records are committed in the same transaction as the associated business change where applicable.
- Added administrator-only user listing and role/active-state management (`admin`, `analyst`, `viewer`). Responses expose account metadata only; password hashes are never returned.
- Prevented administrators from disabling or demoting their own account and prevented removal/deactivation of the last active administrator.
- Added administrator-only, paginated audit-log search by action and actor. No update/delete API is exposed for audit records.
- Added analyst/viewer separation: viewers can read SOC records but cannot update event status, change incident state/assignment, add investigation notes, or record response actions.
- Added bounded incident search with text, status, severity, priority, assignee, source IP, date-range filters and pagination.
- Extended security-event listing filters with event type, username, free-text, risk-score range and time range while preserving existing response shape and pagination parameters.
- Added security response headers. Production mode restricts CORS to the configured frontend origin and disables interactive Swagger/ReDoc/OpenAPI routes; development mode retains local origins and docs.
- Added additive SQLAlchemy table creation for `audit_logs`; existing tables and records are not dropped or rewritten.

### Validation
- Python source compilation (`backend/app`, tests, endpoint agent): passed.
- Phase 10 static authorization/search guardrails and audit persistence test: passed.
- Combined automated regression suite (`backend/tests` plus `endpoint_agent/tests`): **27 passed**.
- Production configuration validation with HTTPS frontend and long random secrets: passed.
- Full FastAPI integration and browser build: require installation of declared dependencies in the Windows project environment; the current offline review runtime does not contain `python-jose` or `pwdlib` and cannot fetch packages.
- Existing SQLite database upgrade: `Base.metadata.create_all()` adds the new audit table on startup; this is an additive bootstrap, not a versioned Alembic migration system. A production multi-instance deployment should introduce Alembic migrations before schema evolution.

### Deployment limits
- Keep one Uvicorn worker while the event hub and WebSocket ticket store are in-memory.
- Use `ENVIRONMENT=production`, HTTPS/WSS, a strong unique `SECRET_KEY`, unique `AGENT_API_KEY`, restricted `FRONTEND_URL`, and a private database backup.
- Rotate previously exposed secrets and administrator credentials before deployment.


## Phase 10 release verification summary

| Area | Result | Notes |
|---|---|---|
| Backend/agent Python syntax | PASS | `compileall` completed |
| Automated regression tests | PASS | 27 passed |
| Audit persistence | PASS | SQLite in-memory persistence test |
| Role and route guardrails | PASS | Static tests cover admin-only and analyst-only route boundaries |
| Production config validation | PASS | HTTPS frontend and strong unique secret values accepted |
| Full FastAPI startup/HTTP/WebSocket | BLOCKED | `python-jose` and `pwdlib` unavailable in offline review runtime |
| React/Vite production build | BLOCKED | npm registry package tarballs unavailable; no node_modules in clean source archive |
| Windows Security Event Log/socket collection | NOT RUN | Requires the target Windows laptop and local permissions |
| Local Ollama investigation | NOT RUN | Requires the user's Ollama service/model |

This release is a development/test candidate, **not yet certified deployment-ready**. Complete the Windows validation checklist in the README before production use.

## v11 real Windows telemetry update (2026-11-09)

Implemented a broader passive Windows event collector in `endpoint_agent/windows_event_monitor.py` and rewired the agent to maintain per-channel checkpoints. It collects selected Security (4624, 4625, 4740, 4720, 4722, 4724, 4728, 4732, 4697, 1102; optional 4688), System (7045), and Defender Operational (1116, 1117) records, plus the existing passive established-TCP observations. First-run history is bounded by `NYENSUNG_INITIAL_BACKFILL_HOURS` (default 24). Stable event request IDs are deduplicated by the backend. High/critical endpoint observations can open incidents.

Sensitive command-line/script contents are not collected. Process creation telemetry is disabled by default. These events are observations/indicators, not proof of an attack. Local Windows validation is still required for audit-policy configuration, channel access, and actual event delivery.

Validation in the build environment: endpoint-agent parser/network tests: 8 passed; backend tests with a test-only `SECRET_KEY` supplied in the environment: 25 passed; Python compileall succeeded. This environment is not Windows, so actual Event Log collection has not been exercised here.
