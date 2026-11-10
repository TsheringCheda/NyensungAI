from datetime import datetime, timedelta, timezone

from app.models.incident import Incident
from app.services.incident_sla import calculate_incident_sla


def make_incident(priority="P1", status="NEW", age_minutes=30):
    created = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=age_minutes)
    return Incident(
        id=1,
        incident_number="NY-TEST-SLA",
        security_event_id=1,
        title="Test incident",
        description="Test",
        severity="HIGH",
        priority=priority,
        status=status,
        created_at=created,
    )


def test_p1_incident_is_on_track_before_target_warning_window():
    result = calculate_incident_sla(make_incident("P1", age_minutes=20), datetime.now(timezone.utc).replace(tzinfo=None))
    assert result["target_minutes"] == 60
    assert result["state"] == "ON_TRACK"
    assert result["remaining_minutes"] > 0


def test_p1_incident_is_breached_after_one_hour():
    result = calculate_incident_sla(make_incident("P1", age_minutes=75), datetime.now(timezone.utc).replace(tzinfo=None))
    assert result["state"] == "BREACHED"
    assert result["remaining_minutes"] == 0


def test_resolved_incident_is_completed_even_after_target():
    result = calculate_incident_sla(make_incident("P2", status="RESOLVED", age_minutes=600), datetime.now(timezone.utc).replace(tzinfo=None))
    assert result["target_minutes"] == 240
    assert result["state"] == "COMPLETED"


def test_unknown_priority_uses_safe_p3_default():
    result = calculate_incident_sla(make_incident("UNKNOWN", age_minutes=10), datetime.now(timezone.utc).replace(tzinfo=None))
    assert result["target_minutes"] == 1440
