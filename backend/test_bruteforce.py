from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models.security_event import SecurityEvent
from app.services.threat_detection import analyze_failed_logins

TEST_IP = "198.51.100.77"
TEST_USERNAME = "NYENSUNG_RISK_TEST"

db = SessionLocal()
test_ids = []

try:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).replace(tzinfo=None)

    existing = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "LOGIN_FAILURE",
        SecurityEvent.source_ip == TEST_IP,
        SecurityEvent.timestamp >= cutoff
    ).count()

    if existing:
        raise RuntimeError(
            "Test stopped: existing recent login failures use this IP."
        )

    for number in range(5):
        event = SecurityEvent(
            event_type="LOGIN_FAILURE",
            source="NyensungAI Automated Test",
            source_ip=TEST_IP,
            username=TEST_USERNAME,
            description=f"Temporary brute-force test event {number + 1}",
            severity="LOW",
            risk_score=0,
            status="NEW",
            is_suspicious=False
        )
        db.add(event)

    db.commit()

    inserted = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "LOGIN_FAILURE",
        SecurityEvent.source_ip == TEST_IP,
        SecurityEvent.username == TEST_USERNAME,
        SecurityEvent.source == "NyensungAI Automated Test",
        SecurityEvent.timestamp >= cutoff
    ).all()

    test_ids = [event.id for event in inserted]

    result = analyze_failed_logins(db, TEST_IP)

    print("\n--- BRUTE-FORCE DETECTION TEST ---")
    print("Detected:", result["detected"])
    print("Failed attempts:", result["failed_attempts"])
    print("Risk score:", result.get("risk_score"))
    print("Severity:", result.get("severity"))
    print("Risk factors:", result.get("risk_factors"))

    assert result["detected"] is True
    assert result["failed_attempts"] == 5
    assert result["risk_score"] == 60
    assert result["severity"] == "HIGH"

    print("\nPASS: Brute-force detection and risk scoring work.")

finally:
    if test_ids:
        db.query(SecurityEvent).filter(
            SecurityEvent.id.in_(test_ids)
        ).delete(synchronize_session=False)
        db.commit()
        print("Temporary test events cleaned up.")

    db.close()
