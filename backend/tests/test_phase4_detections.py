from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.security_event import SecurityEvent
from app.services.web_attack_detection import inspect_web_request
from app.services.credential_abuse_detection import detect_credential_abuse


def make_db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_web_signatures_only_inspect_explicit_web_events():
    db = make_db()
    ordinary = SecurityEvent(
        event_type="SYSTEM_NOTE", source="test", source_ip="192.0.2.10",
        description="GET /?q= UNION SELECT username FROM users"
    )
    db.add(ordinary); db.commit(); db.refresh(ordinary)
    assert inspect_web_request(db, ordinary) == []

    web = SecurityEvent(
        event_type="HTTP_REQUEST_OBSERVED", source="test", source_ip="192.0.2.10",
        description="GET /search?q=UNION%20SELECT%20name%20FROM%20users"
    )
    db.add(web); db.commit(); db.refresh(web)
    alerts = inspect_web_request(db, web)
    assert len(alerts) == 1
    assert alerts[0].event_type == "WEB_SQL_INJECTION_INDICATOR"
    assert "UNION" not in alerts[0].description


def test_web_alert_deduplicates_same_source_and_window():
    db = make_db()
    for path in ("/one?x=<script>alert(1)</script>", "/two?x=javascript:alert(1)"):
        event = SecurityEvent(
            event_type="WEB_REQUEST_OBSERVED", source="test", source_ip="192.0.2.20",
            description=f"GET {path}"
        )
        db.add(event); db.commit(); db.refresh(event)
        inspect_web_request(db, event)
    count = db.query(SecurityEvent).filter_by(event_type="WEB_XSS_INDICATOR").count()
    assert count == 1


def test_path_traversal_indicator():
    db = make_db()
    event = SecurityEvent(
        event_type="WEB_ACCESS_LOG", source="test", source_ip="192.0.2.30",
        description="GET /download?file=..%2f..%2fetc%2fpasswd"
    )
    db.add(event); db.commit(); db.refresh(event)
    alerts = inspect_web_request(db, event)
    assert [a.event_type for a in alerts] == ["WEB_PATH_TRAVERSAL_INDICATOR"]


def test_credential_abuse_requires_repeated_multi_account_pattern():
    db = make_db()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for username in ("alice", "bob", "carol"):
        for _ in range(4):
            db.add(SecurityEvent(
                event_type="LOGIN_FAILURE", source="test", source_ip="192.0.2.40",
                username=username, description="Failed login", timestamp=now
            ))
    db.commit()
    result = detect_credential_abuse(db, "192.0.2.40", now=now)
    assert result["detected"] is True
    assert result["alert_created"] is True
    assert db.query(SecurityEvent).filter_by(event_type="CREDENTIAL_ABUSE_PATTERN").count() == 1


def test_credential_abuse_does_not_trigger_on_single_account():
    db = make_db()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for _ in range(15):
        db.add(SecurityEvent(
            event_type="LOGIN_FAILURE", source="test", source_ip="192.0.2.50",
            username="alice", description="Failed login", timestamp=now
        ))
    db.commit()
    result = detect_credential_abuse(db, "192.0.2.50", now=now)
    assert result["detected"] is False
