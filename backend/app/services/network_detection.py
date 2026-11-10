"""Passive network telemetry detections for authorized endpoint sensors."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent

PORT_PATTERN = re.compile(r"\blocal_port=(\d{1,5})\b", re.IGNORECASE)
SCAN_WINDOW_SECONDS = 60
SCAN_UNIQUE_PORT_THRESHOLD = 8


def detect_possible_port_scan(db: Session, source_ip: str, now: datetime | None = None) -> dict:
    """Flag a possible scan when one remote IP reaches >=8 local TCP ports in 60s.

    This is a heuristic based on endpoint socket observations, not packet-level
    proof. It deliberately emits a medium-severity alert for analyst review.
    """
    if not source_ip:
        return {"detected": False, "reason": "missing_source_ip"}

    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = current - timedelta(seconds=SCAN_WINDOW_SECONDS)
    observations = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "NETWORK_CONNECTION_OBSERVED",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff,
        )
        .all()
    )
    ports = set()
    for item in observations:
        match = PORT_PATTERN.search(item.description or "")
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)

    if len(ports) < SCAN_UNIQUE_PORT_THRESHOLD:
        return {"detected": False, "unique_local_ports": len(ports)}

    existing = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "NETWORK_PORT_SCAN_SUSPECTED",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff,
        )
        .first()
    )
    if existing:
        return {"detected": True, "alert_created": False, "unique_local_ports": len(ports)}

    alert = SecurityEvent(
        event_type="NETWORK_PORT_SCAN_SUSPECTED",
        source="NyensungAI Network Detection Engine",
        source_ip=source_ip,
        description=(
            f"Possible TCP port-scanning behavior: remote endpoint {source_ip} "
            f"was observed connected to {len(ports)} distinct local ports "
            f"within {SCAN_WINDOW_SECONDS} seconds. This heuristic requires analyst validation."
        ),
        severity="MEDIUM",
        risk_score=65,
        status="NEW",
        is_suspicious=True,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return {"detected": True, "alert_created": True, "unique_local_ports": len(ports), "alert_id": alert.id}
