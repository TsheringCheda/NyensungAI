"""Evidence-bounded incident timeline and correlation helpers."""
from datetime import datetime, timedelta, timezone
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.incident import Incident, IncidentAction, IncidentNote
from app.models.security_event import SecurityEvent


def _iso(value):
    return value.isoformat() if value else None


def build_incident_timeline(
    db: Session,
    incident: Incident,
    window_minutes: int = 30,
) -> dict:
    """Build a timeline from the incident's primary event and nearby matching evidence.

    Correlation is exact-match only (source IP, username, or request ID), bounded
    to +/- window_minutes around the primary event. It does not infer causation.
    """
    primary = db.query(SecurityEvent).filter(
        SecurityEvent.id == incident.security_event_id
    ).first()
    if primary is None:
        return {
            "incident_id": incident.id,
            "primary_event": None,
            "related_events": [],
            "timeline": [],
            "risk_summary": {
                "event_count": 0, "max_risk_score": 0,
                "average_risk_score": 0, "severity_counts": {},
            },
            "correlation": {
                "window_minutes": window_minutes,
                "matched_on": [],
                "limitation": "The incident's linked security event is unavailable.",
            },
        }

    event_time = primary.timestamp or incident.created_at
    if event_time is None:
        event_time = datetime.now(timezone.utc).replace(tzinfo=None)
    # SQLite may return naive datetimes even for timezone-aware columns.
    if event_time.tzinfo is not None:
        event_time = event_time.replace(tzinfo=None)
    start, end = event_time - timedelta(minutes=window_minutes), event_time + timedelta(minutes=window_minutes)

    conditions = []
    matched_on = []
    if primary.source_ip:
        conditions.append(SecurityEvent.source_ip == primary.source_ip)
        matched_on.append("source_ip")
    if primary.username:
        conditions.append(SecurityEvent.username == primary.username)
        matched_on.append("username")
    if primary.request_id:
        conditions.append(SecurityEvent.request_id == primary.request_id)
        matched_on.append("request_id")

    related = []
    if conditions:
        related = (db.query(SecurityEvent)
            .filter(SecurityEvent.id != primary.id,
                    SecurityEvent.timestamp >= start,
                    SecurityEvent.timestamp <= end,
                    or_(*conditions))
            .order_by(SecurityEvent.timestamp.asc())
            .limit(200).all())

    events = [primary, *related]
    scores = [max(0, min(100, int(e.risk_score or 0))) for e in events]
    severity_counts = {}
    for event in events:
        key = (event.severity or "UNKNOWN").upper()
        severity_counts[key] = severity_counts.get(key, 0) + 1

    timeline = []
    for event in events:
        timeline.append({
            "kind": "SECURITY_EVENT",
            "id": event.id,
            "timestamp": _iso(event.timestamp),
            "title": event.event_type,
            "description": event.description,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "source_ip": event.source_ip,
            "username": event.username,
            "is_primary": event.id == primary.id,
        })

    notes = db.query(IncidentNote).filter(
        IncidentNote.incident_id == incident.id
    ).all()
    actions = db.query(IncidentAction).filter(
        IncidentAction.incident_id == incident.id
    ).all()
    for note in notes:
        timeline.append({"kind": "ANALYST_NOTE", "id": note.id,
            "timestamp": _iso(note.created_at), "title": "Investigation note",
            "description": note.note, "actor": note.author})
    for action in actions:
        timeline.append({"kind": "RESPONSE_ACTION", "id": action.id,
            "timestamp": _iso(action.created_at), "title": action.action_type,
            "description": action.details, "actor": action.actor,
            "outcome": action.outcome})
    timeline.sort(key=lambda item: item.get("timestamp") or "")

    return {
        "incident_id": incident.id,
        "primary_event": {
            "id": primary.id, "event_type": primary.event_type,
            "timestamp": _iso(primary.timestamp), "source_ip": primary.source_ip,
            "username": primary.username, "severity": primary.severity,
            "risk_score": primary.risk_score,
        },
        "related_events": [item for item in timeline if item["kind"] == "SECURITY_EVENT" and not item.get("is_primary")],
        "timeline": timeline,
        "risk_summary": {
            "event_count": len(events),
            "max_risk_score": max(scores, default=0),
            "average_risk_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "severity_counts": severity_counts,
        },
        "correlation": {
            "window_minutes": window_minutes,
            "matched_on": matched_on,
            "limitation": "Exact metadata matches indicate related evidence, not proof that events share one cause or attacker.",
            "truncated": len(related) >= 200,
        },
    }
