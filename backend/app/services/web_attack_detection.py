"""Conservative application-layer indicator detection for authorized web telemetry.

Only explicitly typed HTTP/web request events are inspected. This module never
executes, blocks, or replays the observed request; it creates analyst-facing
indicators and avoids copying potentially hostile payloads into alert text.
"""
from __future__ import annotations

import re
from urllib.parse import unquote
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.security_event import SecurityEvent

WEB_EVENT_TYPES = {"HTTP_REQUEST_OBSERVED", "WEB_REQUEST_OBSERVED", "WEB_ACCESS_LOG"}
WINDOW_MINUTES = 5

SIGNATURES = {
    "WEB_SQL_INJECTION_INDICATOR": re.compile(
        r"(?:\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,80}\bfrom\b|"
        r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+|--\s|/\*.*?\*/|\bsleep\s*\()",
        re.IGNORECASE | re.DOTALL,
    ),
    "WEB_XSS_INDICATOR": re.compile(
        r"(?:<\s*script\b|javascript\s*:|\bonerror\s*=|\bonload\s*=|"
        r"<\s*svg\b.{0,200}\bonload\s*=|document\.cookie)",
        re.IGNORECASE | re.DOTALL,
    ),
    "WEB_PATH_TRAVERSAL_INDICATOR": re.compile(
        r"(?:\.\.(?:[\\/]|%2f|%5c)|%2e%2e(?:%2f|%5c)|%252e%252e)", re.IGNORECASE
    ),
}

ALERT_META = {
    "WEB_SQL_INJECTION_INDICATOR": ("HIGH", 82, "Possible SQL injection pattern"),
    "WEB_XSS_INDICATOR": ("MEDIUM", 68, "Possible cross-site scripting pattern"),
    "WEB_PATH_TRAVERSAL_INDICATOR": ("HIGH", 78, "Possible path traversal pattern"),
}


def inspect_web_request(db: Session, event: SecurityEvent, now: datetime | None = None) -> list[SecurityEvent]:
    """Inspect explicitly typed web request telemetry and return new alerts."""
    if event.event_type not in WEB_EVENT_TYPES:
        return []

    raw_evidence = " ".join(filter(None, [event.description, event.user_agent or ""]))[:12000]
    evidence = unquote(unquote(raw_evidence))
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = current - timedelta(minutes=WINDOW_MINUTES)
    created: list[SecurityEvent] = []

    for alert_type, signature in SIGNATURES.items():
        if not signature.search(evidence):
            continue
        existing_query = db.query(SecurityEvent).filter(
            SecurityEvent.event_type == alert_type,
            SecurityEvent.timestamp >= cutoff,
        )
        if event.source_ip:
            existing_query = existing_query.filter(SecurityEvent.source_ip == event.source_ip)
        else:
            existing_query = existing_query.filter(SecurityEvent.source_ip.is_(None))
        if existing_query.first():
            continue

        severity, risk, label = ALERT_META[alert_type]
        alert = SecurityEvent(
            event_type=alert_type,
            source="NyensungAI Web Request Detection Engine",
            source_ip=event.source_ip,
            username=event.username,
            description=(
                f"{label} observed in an explicitly identified web request event "
                f"(event ID {event.id}). This signature is an indicator, not proof "
                "of exploitation; validate the request, response, and application context."
            ),
            severity=severity,
            risk_score=risk,
            status="NEW",
            is_suspicious=True,
        )
        db.add(alert)
        db.flush()
        created.append(alert)

    if created:
        db.commit()
        for alert in created:
            db.refresh(alert)
    return created
