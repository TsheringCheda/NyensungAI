import json
import urllib.request
import uuid

from app.config import settings
from app.database import SessionLocal
from app.models.security_event import SecurityEvent
from app.models.incident import Incident

API_URL = "http://127.0.0.1:8000/api/security-events/"
TEST_IP = "198.51.100.88"
TEST_USERNAME = "NYENSUNG_API_TEST_" + uuid.uuid4().hex[:10]
TEST_SOURCE = "NyensungAI API Integration Test"

def submit_failure(index):
    payload = {
        "event_type": "LOGIN_FAILURE",
        "source": TEST_SOURCE,
        "source_ip": TEST_IP,
        "username": TEST_USERNAME,
        "description": f"Synthetic failed-login test event {index}",
        "severity": "LOW",
        "risk_score": 0,
        "status": "NEW",
        "is_suspicious": False,
        "auth_result": "FAILURE",
        "failure_reason": "INVALID_PASSWORD",
        "request_id": str(uuid.uuid4())
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Agent-Key": settings.AGENT_API_KEY
        },
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


if not settings.AGENT_API_KEY:
    raise RuntimeError("AGENT_API_KEY is not configured.")

db = SessionLocal()

try:
    print("\n--- NYENSUNGAI API BRUTE-FORCE TEST ---")

    for i in range(1, 6):
        result = submit_failure(i)
        print(f"Login failure {i}: accepted (event ID {result['id']})")

    alert = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "BRUTE_FORCE_DETECTED",
        SecurityEvent.source_ip == TEST_IP,
        SecurityEvent.username == TEST_USERNAME
    ).first()

    assert alert is not None, "Brute-force alert was not created."

    print("\nBrute-force alert detected.")
    print("Risk score:", alert.risk_score)
    print("Severity:", alert.severity)

    assert alert.risk_score == 60, "Expected risk score 60."
    assert alert.severity == "HIGH", "Expected HIGH severity."

    incident = db.query(Incident).filter(
        Incident.security_event_id == alert.id
    ).first()

    assert incident is not None, "P2 incident was not created."
    assert incident.priority == "P2", "Expected P2 incident."

    print("Incident:", incident.incident_number)
    print("Incident priority:", incident.priority)

    # Submit one more failure to verify duplicate alert prevention.
    submit_failure(6)

    db.expire_all()

    alert_count = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "BRUTE_FORCE_DETECTED",
        SecurityEvent.source_ip == TEST_IP,
        SecurityEvent.username == TEST_USERNAME
    ).count()

    incident_count = db.query(Incident).filter(
        Incident.security_event_id == alert.id
    ).count()

    assert alert_count == 1, "Duplicate brute-force alert detected."
    assert incident_count == 1, "Duplicate incident detected."

    print("\nDuplicate prevention: PASS")
    print("\nALL API TESTS PASSED.")

finally:
    # Remove only records belonging to this unique synthetic test.
    db.expire_all()

    test_events = db.query(SecurityEvent).filter(
        SecurityEvent.source_ip == TEST_IP,
        SecurityEvent.username == TEST_USERNAME
    ).all()

    test_ids = [event.id for event in test_events]

    if test_ids:
        db.query(Incident).filter(
            Incident.security_event_id.in_(test_ids)
        ).delete(synchronize_session=False)

        db.query(SecurityEvent).filter(
            SecurityEvent.id.in_(test_ids)
        ).delete(synchronize_session=False)

        db.commit()

    print("Synthetic test records cleaned up.")
    db.close()
