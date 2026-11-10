"""Detect repeated multi-account authentication abuse indicators."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.security_event import SecurityEvent

WINDOW_MINUTES = 10
MIN_FAILURES = 12
MIN_TARGETS = 3
MIN_REPEATED_TARGETS = 3
MIN_ATTEMPTS_PER_REPEATED_TARGET = 4


def detect_credential_abuse(db: Session, source_ip: str, now: datetime | None = None) -> dict:
    """Flag sustained failures repeated across several accounts.

    This is an account-targeting heuristic. It cannot establish that stolen
    credential pairs were used, because passwords are never collected.
    """
    if not source_ip:
        return {"detected": False, "reason": "missing_source_ip"}
    current = now or datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = current - timedelta(minutes=WINDOW_MINUTES)
    events = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "LOGIN_FAILURE",
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.timestamp >= cutoff,
        SecurityEvent.username.isnot(None),
    ).all()
    counts = Counter(
        e.username.strip().casefold() for e in events if e.username and e.username.strip()
    )
    total = sum(counts.values())
    repeated = sum(1 for count in counts.values() if count >= MIN_ATTEMPTS_PER_REPEATED_TARGET)
    detected = total >= MIN_FAILURES and len(counts) >= MIN_TARGETS and repeated >= MIN_REPEATED_TARGETS
    if not detected:
        return {"detected": False, "failed_attempts": total, "targeted_accounts": len(counts), "repeated_targets": repeated}

    existing = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "CREDENTIAL_ABUSE_PATTERN",
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.timestamp >= cutoff,
    ).first()
    if existing:
        return {"detected": True, "alert_created": False, "failed_attempts": total, "targeted_accounts": len(counts)}

    alert = SecurityEvent(
        event_type="CREDENTIAL_ABUSE_PATTERN",
        source="NyensungAI Authentication Abuse Detection Engine",
        source_ip=source_ip,
        description=(
            f"Repeated failed authentication activity affected {len(counts)} distinct accounts, "
            f"with {repeated} accounts receiving at least {MIN_ATTEMPTS_PER_REPEATED_TARGET} failures "
            f"each in {WINDOW_MINUTES} minutes. This may indicate credential abuse; "
            "credential stuffing cannot be confirmed without additional identity-provider evidence."
        ),
        severity="HIGH",
        risk_score=78,
        status="NEW",
        is_suspicious=True,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return {"detected": True, "alert_created": True, "alert_id": alert.id, "failed_attempts": total, "targeted_accounts": len(counts)}
