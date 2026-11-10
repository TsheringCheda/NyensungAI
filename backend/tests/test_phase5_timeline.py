from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.security_event import SecurityEvent
from app.models.incident import Incident, IncidentNote, IncidentAction
from app.services.incident_timeline import build_incident_timeline


def make_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def add_event(db, event_type, at, ip=None, username=None, score=0, severity="LOW", request_id=None):
    item = SecurityEvent(event_type=event_type, source="test", source_ip=ip,
        username=username, description="test evidence", severity=severity,
        risk_score=score, status="NEW", is_suspicious=False,
        request_id=request_id, timestamp=at)
    db.add(item); db.flush(); return item


def test_timeline_correlates_exact_ip_and_includes_analyst_activity():
    db = make_db(); now = datetime.now(timezone.utc).replace(tzinfo=None)
    primary = add_event(db, "BRUTE_FORCE_DETECTED", now, "192.0.2.10", "alice", 85, "HIGH")
    add_event(db, "LOGIN_FAILURE", now + timedelta(minutes=2), "192.0.2.10", "bob", 30)
    add_event(db, "UNRELATED", now + timedelta(minutes=2), "198.51.100.8", "mallory", 99, "CRITICAL")
    incident = Incident(incident_number="NY-TEST-0001", security_event_id=primary.id,
        title="Brute force", description="test", severity="HIGH", priority="P2",
        status="NEW", source_ip="192.0.2.10")
    db.add(incident); db.flush()
    db.add(IncidentNote(incident_id=incident.id, author="analyst", note="Reviewed source"))
    db.add(IncidentAction(incident_id=incident.id, actor="analyst", action_type="CONTAINMENT_RECOMMENDED",
        details="Review endpoint", outcome="RECORDED")); db.commit()

    result = build_incident_timeline(db, incident)
    assert len(result["related_events"]) == 1
    assert result["risk_summary"]["event_count"] == 2
    assert result["risk_summary"]["max_risk_score"] == 85
    assert {row["kind"] for row in result["timeline"]} == {"SECURITY_EVENT", "ANALYST_NOTE", "RESPONSE_ACTION"}
    assert result["correlation"]["matched_on"] == ["source_ip", "username"]
    db.close()


def test_timeline_does_not_correlate_null_identifiers_or_out_of_window_events():
    db = make_db(); now = datetime.now(timezone.utc).replace(tzinfo=None)
    primary = add_event(db, "ALERT", now, None, None, 20)
    add_event(db, "NULL_ID_EVENT", now, None, None, 90, "CRITICAL")
    add_event(db, "OLD_EVENT", now - timedelta(hours=2), "192.0.2.1", "alice", 90, "CRITICAL")
    incident = Incident(incident_number="NY-TEST-0002", security_event_id=primary.id,
        title="Alert", description="test", severity="LOW", priority="P4", status="NEW")
    db.add(incident); db.commit()
    result = build_incident_timeline(db, incident, window_minutes=30)
    assert result["related_events"] == []
    assert result["risk_summary"]["event_count"] == 1
    db.close()


def test_timeline_window_is_configurable_and_request_id_correlates():
    db = make_db(); now = datetime.now(timezone.utc).replace(tzinfo=None)
    primary = add_event(db, "WEB_ALERT", now, None, None, 65, "HIGH", "req-123")
    add_event(db, "WEB_ACCESS_LOG", now + timedelta(minutes=10), None, None, 10, "LOW", "req-123")
    incident = Incident(incident_number="NY-TEST-0003", security_event_id=primary.id,
        title="Web alert", description="test", severity="HIGH", priority="P2", status="NEW")
    db.add(incident); db.commit()
    result = build_incident_timeline(db, incident, window_minutes=15)
    assert len(result["related_events"]) == 1
    assert result["correlation"]["matched_on"] == ["request_id"]
    db.close()
