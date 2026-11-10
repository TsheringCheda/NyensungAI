
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.services.risk_scoring import calculate_risk_score


# =========================================
# BRUTE FORCE DETECTION CONFIGURATION
# =========================================

FAILED_LOGIN_THRESHOLD = 5
DETECTION_WINDOW_MINUTES = 10


# =========================================
# DETECT REPEATED FAILED LOGIN ATTEMPTS
# =========================================

def analyze_failed_logins(
    db: Session,
    source_ip: str
):

    if not source_ip:
        return {
            "detected": False,
            "message": "Source IP is required."
        }

    # SQLite commonly returns timezone-naive datetimes.
    cutoff_time = (
        datetime.now(timezone.utc)
        - timedelta(minutes=DETECTION_WINDOW_MINUTES)
    ).replace(tzinfo=None)

    # Count failed login events from this IP.
    recent_failures = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type == "LOGIN_FAILURE",
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= cutoff_time
        )
        .count()
    )

    # Check whether the threshold has been reached.
    if recent_failures >= FAILED_LOGIN_THRESHOLD:

        risk = calculate_risk_score(
            failed_logins=recent_failures,
            is_brute_force_detected=True
        )

        return {
            "detected": True,
            "threat_type": "BRUTE_FORCE_ATTACK",
            "source_ip": source_ip,
            "failed_attempts": recent_failures,
            "time_window_minutes": DETECTION_WINDOW_MINUTES,
            "severity": risk["severity"],
            "risk_score": risk["risk_score"],
            "risk_factors": risk["risk_factors"],
            "scoring_method": risk["scoring_method"],
            "is_suspicious": True,
            "message": (
                "Repeated failed login attempts detected."
            )
        }

    return {
        "detected": False,
        "source_ip": source_ip,
        "failed_attempts": recent_failures,
        "required_attempts": FAILED_LOGIN_THRESHOLD,
        "message": "No brute-force threshold reached."
    }
