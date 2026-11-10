# NyensungAI documentation

Use the root `README.md` for the current setup and implementation guide.

## Phase 7 update — analyst assignment and response targets

The incident workspace now supports analyst assignment and displays priority-based operational response-target status.

- Assign an incident by entering the existing analyst username in the incident detail panel.
- Assignment changes are written to the response action history.
- The authenticated endpoint `GET /api/incidents/sla/summary` returns per-incident target status and aggregate counts.
- Default target windows: P1 60 minutes, P2 4 hours, P3 24 hours, P4 72 hours.
- Target states: ON_TRACK, AT_RISK, BREACHED and COMPLETED.

These are configurable operational defaults calculated from incident creation time and priority, not contractual SLAs. Review and adjust them for your environment before production use.

The incident workflow now correctly permits `RESOLVED -> CLOSED` after the required resolution explanation has been recorded.
