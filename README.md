# NyensungAI

**NyensungAI — Intelligent Cyber Threat Detection and Incident Response Platform**

A defensive security operations MVP for collecting authentication/security events, identifying suspicious activity, correlating evidence, supporting AI-assisted investigations, and managing incident records.

## Latest repair notes

- The frontend now normalizes the configured API root and corrects a trailing `/api/n` typo to `/api`. This prevents login requests from being sent to `/api/n/auth/login`; the backend authentication route remains `/api/auth/login`.
- Frontend API errors are parsed safely when the server returns a non-JSON error page, so route mistakes produce a useful message instead of a JSON parsing exception.
- The frontend `.env.example` has been corrected to a single valid `VITE_API_BASE_URL` line. If you already have `frontend/.env`, verify that it contains `VITE_API_BASE_URL=http://127.0.0.1:8000/api`.
- The backend health endpoint performs a real database connectivity check.
- Python syntax compilation passed in the repair environment. A complete frontend build and live Ollama/database integration test still need to be run on the Windows development machine.

## What is included in this update

- Existing FastAPI + SQLAlchemy backend and React + TypeScript frontend retained.
- AI investigation results now open in a dedicated report dialog with loading, error, evidence, assessment, recommendations, and limitations sections.
- Investigation requests have a 5.5-minute browser timeout aligned with the local Ollama request window, and unexpected response payloads are reported clearly.
- Historical authentication evidence counters now fall back to legacy `event_type` values when older rows have no `auth_result`.
- Threat Monitoring page displays recent event telemetry and the backend's 24-hour activity buckets, refreshing at the configured browser interval.
- Reports page exports the currently loaded event and incident records as CSV and a combined JSON snapshot.
- Settings page checks API/database health and saves a browser-only monitoring refresh preference.
- API base URL can be configured through `frontend/.env`.
- Backend health now checks an actual database connection instead of returning a hard-coded healthy state.

## Technology

- Backend: Python, FastAPI, SQLAlchemy, SQLite (local development)
- Frontend: React, TypeScript, Vite
- AI: Ollama with `qwen3:4b` (local model)
- Detection: rule-based authentication detection and Isolation Forest anomaly detection
- Optional endpoint telemetry: Windows Event Log agent

## Local development setup (Windows PowerShell)

### 1. Prerequisites

Install:
- Python 3.11 or 3.12 (match the version supported by the pinned dependencies)
- Node.js LTS and npm
- Ollama
- Git (optional)

### 2. Backend

Open PowerShell:

```powershell
cd .\backend
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Open `backend\.env` and replace `SECRET_KEY` with a long random secret. Do not commit or share `.env`.

Generate a secret in PowerShell:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated value into `SECRET_KEY` in `.env`.

Start the API:

```powershell
python -m uvicorn app.main:app --reload
```

API root: `http://127.0.0.1:8000/`  
API documentation: `http://127.0.0.1:8000/docs`  
Health check: `http://127.0.0.1:8000/api/health`

The SQLite database is created automatically as `backend\sentinelai.db` on first startup. This source package intentionally excludes the uploaded runtime database and backup files. If you need your existing local users/events, copy your own `sentinelai.db` into `backend` before starting the backend. Keep a backup first.

### 3. Ollama AI model

Install Ollama, then run:

```powershell
ollama pull qwen3:4b
ollama serve
```

Ollama normally runs as a background service on Windows. Verify the model is available:

```powershell
ollama list
```

The backend investigation service currently expects Ollama at `http://localhost:11434` and model `qwen3:4b`. If you change either, update `backend\app\services\llm_investigation.py`.

AI analysis is advisory. It does not independently prove compromise and does not execute firewall, account, or network response actions.

### 4. Frontend

Open a second PowerShell window:

```powershell
cd .\frontend
Copy-Item .env.example .env
npm ci
npm run dev
```

Open `http://localhost:5173/`.

If the backend runs on another host/port, set `VITE_API_BASE_URL` in `frontend\.env`, for example:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
```

Build for deployment:

```powershell
npm run build
```

### 5. Optional Windows endpoint agent

The agent is intended for a controlled Windows lab. Review `endpoint_agent\config.py` and `endpoint_agent\requirements.txt` before running it. Install its dependencies in a separate virtual environment and run with the permissions needed to read Windows Security Event Logs.

Do not deploy the current unauthenticated local event-ingestion endpoint to an untrusted network. Before multi-host or production deployment, add agent authentication (for example, per-agent credentials or mutual TLS), TLS, network restrictions, rate limits, and server-side authorization.

## Functional areas

| Area | Current implementation |
|---|---|
| Dashboard | Backend-backed event/threat/incident statistics, activity chart and recent alerts |
| Security Alerts | Search/filter, AI investigation report, create incident from eligible suspicious events |
| Threat Monitoring | Event table, search, 24-hour activity timeline and periodic refresh |
| Incident Response | Incident lifecycle, analyst notes, response action log and AI investigation |
| Reports | CSV exports for loaded events/incidents and combined JSON snapshot |
| Settings | API/database health check and browser-local monitoring refresh preference |
| AI investigation | Ollama-backed evidence analysis; evidence and AI report are separate |
| Endpoint agent | Optional Windows Security Event Log collector for event IDs 4624/4625 |

## Important scope and limitations

- Reports export the records currently loaded by the API (the event page requests up to 100 records). This is not a full forensic archive.
- Settings currently stores only a browser-side refresh preference. It does not alter backend detection thresholds or endpoint-agent configuration.
- Threat Monitoring receives authenticated WebSocket event pushes for new endpoint events and retains periodic polling as a fallback. The in-memory WebSocket hub supports a single backend process; multi-worker deployment requires Redis pub/sub or an equivalent shared broker.
- ML anomaly detection remains dependent on the existing model/baseline implementation and should be validated with representative lab telemetry before operational use.
- Local SQLite and the development CORS configuration are for local development. Use a managed database, HTTPS, restricted CORS, secrets management, backups, authentication/authorization hardening, and audit review before deployment.
- The endpoint agent's checkpoint file prevents replaying already processed Windows event record IDs. Back up and protect it as operational state.

## Validation notes

The Python backend source passed a syntax compilation check in the review environment. A complete backend import/integration test could not be run there because the environment did not have the project's installed Python dependencies (`python-jose` was missing). The uploaded `node_modules` were Windows-specific and could not be used for a Linux frontend production build; run `npm ci` and `npm run build` on the target Windows development machine.

## Project safety

Never commit:
- `backend/.env`
- database files containing real users or security events
- access tokens, passwords, API keys, or signing secrets
- endpoint-agent checkpoint files if they reveal sensitive host activity

Keep `.env.example` files with placeholders in source control.


## Credential rotation before deployment

The source archive supplied for review included a backend `.env` file. The cleaned project package excludes it. Treat any values from that file as exposed: generate a fresh `SECRET_KEY`, rotate any API/agent keys, and change the administrator password before deployment. Never commit or share `.env`; use `.env.example` only as a template.

See [DEVELOPMENT_STATUS.md](./DEVELOPMENT_STATUS.md) for the verified changes, test results, current security gaps, and remaining SOC-platform milestones.


## Secure endpoint-agent setup (local lab)

1. Create a fresh agent key (PowerShell):

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

2. Copy `backend/.env.example` to `backend/.env`. Set a new `SECRET_KEY` and set `AGENT_API_KEY` to the generated value. Do not commit this file.
3. Copy `endpoint_agent/.env.example` to `endpoint_agent/.env`. Set `NYENSUNG_AGENT_API_KEY` to the same agent key. Keep this file private.
4. Install endpoint-agent dependencies with `pip install -r requirements.txt` from `endpoint_agent`. Run the agent from an elevated PowerShell session only if required to read the Windows Security log.
5. Restart the backend after changing its `.env`. The event ingestion endpoint intentionally returns HTTP 503 until `AGENT_API_KEY` is configured and HTTP 401 for a missing or invalid key.

The agent key is separate from the user's login token. WebSocket clients authenticate using their existing short-lived bearer access token in the connection query string; use HTTPS/WSS outside localhost. Avoid logging full WebSocket URLs because they contain the token.

## Live stream deployment note

The current event hub is process-local and designed for the initial one-process Windows lab deployment (`uvicorn ...` with one worker). Do not scale to multiple Uvicorn workers until a shared pub/sub backend is added.

## Passive network telemetry (development phase 3)

The Windows endpoint agent now includes an **optional-by-availability passive TCP socket observer** using `psutil`. It enumerates established TCP sockets, emits one `NETWORK_CONNECTION_OBSERVED` event when a socket first appears, and suppresses repeats while that socket remains in the current snapshot. It does not scan hosts, capture packet payloads, inject packets, or change firewall/network settings.

The backend applies a heuristic: if one remote IP is associated with at least eight distinct local TCP ports in a 60-second window, it creates a medium-severity `NETWORK_PORT_SCAN_SUSPECTED` alert. Treat this as a triage indicator only. Windows socket enumeration does not reliably establish connection direction, so outbound ephemeral connections can resemble multi-port inbound activity. Packet/flow telemetry and direction-aware network sensors are needed for stronger port-scan conclusions. Socket enumeration may require running the agent elevated; access-denied conditions are logged and do not stop authentication-log collection.

Install the additional agent dependency with `pip install -r endpoint_agent/requirements.txt`.

## Phase 4 detection telemetry contract

The application-layer detector only analyzes events submitted with one of these explicit `event_type` values:

- `HTTP_REQUEST_OBSERVED`
- `WEB_REQUEST_OBSERVED`
- `WEB_ACCESS_LOG`

For example, an authorized web application or reverse-proxy adapter may submit a normalized request line/path/query in `description`, along with the observed `source_ip`. Do not include passwords, session cookies, authorization headers, or other secrets. These signatures create analyst-facing indicators; they do not prove exploitation and do not block requests.

Authentication abuse telemetry uses `LOGIN_FAILURE` events with a source IP and username. Never collect or store submitted passwords. `CREDENTIAL_ABUSE_PATTERN` means repeated multi-account failures met the configured heuristic; it does not establish credential stuffing or account compromise.

Run the phase 4 service tests from `backend` after installing backend requirements:

```powershell
$env:SECRET_KEY = "<temporary-test-secret>"
python -m pytest tests/test_phase4_detections.py -q
```

### Phase 5 — incident investigation timeline

Authenticated analysts can retrieve an evidence-bounded incident timeline:

`GET /api/incidents/{incident_id}/timeline?window_minutes=30`

The endpoint combines the incident's primary security event with events matching its exact source IP, username, or request ID within the selected time window, plus analyst notes and recorded response actions. The window is configurable from 1 to 240 minutes. It returns event count, max/average risk score, and severity counts. Correlation is contextual evidence only—not proof of a common attacker or causal relationship. The endpoint requires the same bearer-token authentication as other incident APIs.

## Phase 6 — Incident evidence timeline

Open **Incident Response → Manage** on an incident to view its evidence summary and chronological timeline. The panel displays the primary/related security events, analyst notes, response actions, risk aggregates, severity counts, and correlation window. Correlation is based on exact source-IP, username, or request-ID matches in a bounded time window; it does not prove common causation.

For frontend verification, run `npm ci` in `frontend/` followed by `npm run build`. The frontend build was not completed in the Phase 6 review environment because dependency installation did not finish.


## Phase 9 — WebSocket security update

Threat Monitoring now obtains a 30-second, single-use WebSocket ticket through the authenticated endpoint `POST /api/auth/ws-ticket`. The browser connects to `/api/security-events/ws?ticket=...`; do not manually place a bearer JWT in a WebSocket URL. The backend validates ticket expiry/reuse, the associated token revocation state, active user, and browser Origin. The monitoring page retains periodic HTTP polling as a fallback.

The ticket store and event fan-out are in-memory and support a single backend process. Keep one Uvicorn worker for this local build. A multi-worker deployment must use a shared atomic ticket store and shared pub/sub before enabling multiple workers. Use HTTPS/WSS and disable query-string logging at the reverse proxy.

For verification on Windows:

```powershell
cd "$HOME\Desktop\NyensungAI\backend"
.\venv\Scripts\Activate.ps1
$env:SECRET_KEY = "YOUR_NEW_RANDOM_SECRET"
python -m pytest tests -q
python -m uvicorn app.main:app --reload
```

In another PowerShell window, build the frontend:

```powershell
cd "$HOME\Desktop\NyensungAI\frontend"
npm ci
npm run build
npm run dev
```

Replace the placeholder secret locally with a newly generated value; never paste it into chat or commit it.


## Phase 10 — administration, audit and search

- Roles: `admin` manages accounts and audit logs; `analyst` investigates and updates incidents/events; `viewer` has read-only access.
- Admin account APIs: `GET /api/auth/users`, `PATCH /api/auth/users/{user_id}`.
- Admin audit API: `GET /api/auth/audit-logs?page=1&page_size=50&action=...&actor=...`.
- Incident search: `GET /api/incidents/search` with `q`, `status`, `severity`, `priority`, `assigned_to`, `source_ip`, `since`, `until`, `page`, and `page_size`.
- Security-event listing additionally accepts `event_type`, `username`, `q`, `min_risk`, `max_risk`, `since`, and `until`.
- Set `ENVIRONMENT=production` to disable Swagger/ReDoc/OpenAPI and restrict CORS to `FRONTEND_URL`. Use HTTPS/WSS in production.
- New audit storage is additive: the existing startup table-creation step creates `audit_logs` without deleting existing records. This project does not yet include Alembic versioned migrations.


## Phase 10 validation and release checklist

Run these commands from PowerShell on the Windows development machine after installing dependencies:

```powershell
# Backend
cd "$HOME\Desktop\NyensungAI\backend"
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SECRET_KEY = "<temporary-test-secret>"
python -m pytest -q tests ..\endpoint_agent\tests
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd "$HOME\Desktop\NyensungAI\frontend"
npm ci
npm run build
npm run dev
```

Then verify administrator login, user role changes, viewer read-only behavior, audit log entries, incident search filters, endpoint agent authentication, live WebSocket connection, Windows event collection and local Ollama investigation. The test-only `SECRET_KEY` above is not a deployment value.

Before any deployment: create a database backup; rotate backend `SECRET_KEY`, `AGENT_API_KEY`, endpoint-agent key and administrator password; configure `ENVIRONMENT=production`, a real HTTPS `FRONTEND_URL`, HTTPS/WSS termination, restricted network access and log/query-string redaction. Do not publish `.env` files.
