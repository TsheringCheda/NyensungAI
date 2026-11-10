
from datetime import datetime, timedelta, timezone
from collections import Counter

from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


# =========================================
# PASSWORD SPRAYING CONFIGURATION
# =========================================

DETECTION_WINDOW_MINUTES = 10

MIN_FAILED_ATTEMPTS = 5

MIN_UNIQUE_USERNAMES = 5

MAX_FAILURES_PER_USERNAME = 3


# =========================================
# PASSWORD SPRAYING DETECTION
# =========================================

def detect_password_spraying(
    db: Session,
    source_ip: str
):

    if not source_ip:
        return {
            "detected": False,
            "message": "Source IP is required."
        }

    # Calculate detection window
    cutoff_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=DETECTION_WINDOW_MINUTES)
    ).replace(tzinfo=None)

    # Retrieve recent failed authentication events
    failed_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "LOGIN_FAILURE",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time,
            SecurityEvent.username.isnot(None)
        )
        .all()
    )

    # Normalize usernames
    usernames = [
        event.username.strip().lower()
        for event in failed_events
        if event.username and event.username.strip()
    ]

    # Count attempts per username
    username_counts = Counter(usernames)

    total_failures = len(usernames)

    unique_usernames = len(username_counts)

    max_failures_per_username = (
        max(username_counts.values())
        if username_counts else 0
    )

    # Evaluate password spraying pattern
    detected = (
        total_failures >= MIN_FAILED_ATTEMPTS
        and unique_usernames >= MIN_UNIQUE_USERNAMES
        and max_failures_per_username <= MAX_FAILURES_PER_USERNAME
    )

    if not detected:
        return {
            "detected": False,
            "total_failed_attempts": total_failures,
            "unique_usernames": unique_usernames,
            "max_failures_per_username": max_failures_per_username,
            "message": "No password spraying pattern detected."
        }

    # Prevent duplicate alerts
    existing_alert = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "PASSWORD_SPRAYING_DETECTED",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time
        )
        .first()
    )

    if existing_alert:
        return {
            "detected": True,
            "alert_created": False,
            "message": "Password spraying alert already exists."
        }

    # Create password spraying alert
    alert = SecurityEvent(
        event_type="PASSWORD_SPRAYING_DETECTED",
        source="NyensungAI Password Spraying Detection Engine",
        source_ip=source_ip,
        username=None,
        description=(
            "Potential password spraying activity detected. "
            f"{total_failures} failed login attempts were recorded "
            f"across {unique_usernames} different usernames "
            f"within {DETECTION_WINDOW_MINUTES} minutes."
        ),
        severity="HIGH",
        risk_score=85,
        status="NEW",
        is_suspicious=True
    )

    db.add(alert)
    db.commit()

    return {
        "detected": True,
        "alert_created": True,
        "total_failed_attempts": total_failures,
        "unique_usernames": unique_usernames,
        "max_failures_per_username": max_failures_per_username,
        "time_window_minutes": DETECTION_WINDOW_MINUTES,
        "severity": "HIGH",
        "risk_score": 85,
        "message": "Potential password spraying activity detected."
    }
