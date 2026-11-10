from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.incident import Incident, IncidentNote, IncidentAction
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.routers.auth import get_current_user, require_role
from app.services.audit import write_audit_log
from app.services.incident_sla import SLA_TARGET_MINUTES, calculate_incident_sla
from app.schemas.incident import (
    IncidentUpdate,
    IncidentNoteCreate,
    IncidentActionCreate,
    IncidentResponse,
)


router = APIRouter(
    prefix="/api/incidents",
    tags=["Incident Response"]
)


# =====================================================
# INCIDENT CONFIGURATION
# =====================================================

ELIGIBLE_EVENT_TYPES = {
    "BRUTE_FORCE_DETECTED",
    "PASSWORD_SPRAYING_DETECTED",
    "ML_ANOMALY_DETECTED",
    "RATE_LIMIT_TRIGGERED",
}

# Allowed forward status transitions
ALLOWED_TRANSITIONS = {
    "NEW": {"INVESTIGATING"},
    "INVESTIGATING": {"CONTAINED"},
    "CONTAINED": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set(),
}


# =====================================================
# HELPER FUNCTIONS
# =====================================================

def _priority(severity: str) -> str:
    return {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
    }.get(severity.upper(), "P3")


def _ensure_incident_for_event(
    db: Session,
    event: SecurityEvent
) -> Incident | None:

    if (
        event.event_type not in ELIGIBLE_EVENT_TYPES
        or event.severity not in ("HIGH", "CRITICAL")
    ):
        return None

    existing = (
        db.query(Incident)
        .filter(Incident.security_event_id == event.id)
        .first()
    )

    if existing:
        return None

    item = Incident(
        incident_number=(
            f"NY-{datetime.now(timezone.utc):%Y%m%d}-"
            f"{uuid4().hex[:6].upper()}"
        ),
        security_event_id=event.id,
        title=event.event_type.replace("_", " ").title(),
        description=event.description,
        severity=event.severity,
        priority=_priority(event.severity),
        status="NEW",
        source_ip=event.source_ip,
    )

    db.add(item)

    return item


def _detail(db: Session, incident_id: int):

    item = (
        db.query(Incident)
        .options(
            joinedload(Incident.notes),
            joinedload(Incident.actions)
        )
        .filter(Incident.id == incident_id)
        .first()
    )

    if not item:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return item


def _record_status_change(
    db: Session,
    incident: Incident,
    old_status: str,
    new_status: str,
    username: str,
):

    action = IncidentAction(
        incident_id=incident.id,
        actor=username,
        action_type="STATUS_CHANGED",
        details=(
            f"Incident status changed from "
            f"{old_status} to {new_status}"
        ),
        outcome="RECORDED",
    )

    db.add(action)


# =====================================================
# LIST INCIDENTS
# =====================================================

@router.get("/", response_model=list[IncidentResponse])
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):

    # Backfill eligible alerts that do not yet have incidents.
    eligible_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_type.in_(ELIGIBLE_EVENT_TYPES),
            SecurityEvent.severity.in_(["HIGH", "CRITICAL"]),
        )
        .all()
    )

    created_any = False

    for event in eligible_events:
        if _ensure_incident_for_event(db, event):
            created_any = True

    if created_any:
        db.commit()

    query = db.query(Incident).order_by(
        Incident.created_at.desc()
    )

    if status:
        query = query.filter(
            Incident.status == status.upper()
        )

    if severity:
        query = query.filter(
            Incident.severity == severity.upper()
        )

    return query.limit(limit).all()


# =====================================================
# INCIDENT SUMMARY
# =====================================================

@router.get("/search")
def search_incidents(
    q: str | None = Query(None, max_length=200),
    status: str | None = Query(None, max_length=30),
    severity: str | None = Query(None, max_length=20),
    priority: str | None = Query(None, max_length=5),
    assigned_to: str | None = Query(None, max_length=100),
    source_ip: str | None = Query(None, max_length=45),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Filterable, bounded incident search for SOC analyst workflows."""
    if since and until and since > until:
        raise HTTPException(status_code=422, detail="since must be earlier than until")
    query = db.query(Incident)
    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(
            (Incident.incident_number.ilike(term))
            | (Incident.title.ilike(term))
            | (Incident.description.ilike(term))
            | (Incident.source_ip.ilike(term))
        )
    if status:
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if priority:
        query = query.filter(Incident.priority == priority.upper())
    if assigned_to:
        query = query.filter(Incident.assigned_to.ilike(f"%{assigned_to.strip()}%"))
    if source_ip:
        query = query.filter(Incident.source_ip == source_ip.strip())
    if since:
        query = query.filter(Incident.created_at >= since)
    if until:
        query = query.filter(Incident.created_at <= until)
    total = query.count()
    rows = query.order_by(Incident.created_at.desc(), Incident.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [IncidentResponse.model_validate(row).model_dump(mode="json") for row in rows],
        "page": page, "page_size": page_size, "total": total,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/summary/counts")
def incident_counts(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):

    rows = (
        db.query(
            Incident.status,
            func.count(Incident.id)
        )
        .group_by(Incident.status)
        .all()
    )

    result = {
        "NEW": 0,
        "INVESTIGATING": 0,
        "CONTAINED": 0,
        "RESOLVED": 0,
        "CLOSED": 0,
    }

    for status, count in rows:
        result[status] = count

    result["total"] = sum(result.values())

    return result


# =====================================================
# CREATE INCIDENT FROM SECURITY EVENT
# =====================================================

@router.post(
    "/from-event/{event_id}",
    response_model=IncidentResponse,
    status_code=201
)
def create_incident_from_event(
    event_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event not found"
        )

    if event.event_type not in ELIGIBLE_EVENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail="This event type cannot be escalated automatically"
        )

    existing = (
        db.query(Incident)
        .filter(Incident.security_event_id == event.id)
        .first()
    )

    if existing:
        return existing

    item = _ensure_incident_for_event(db, event)

    if item is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only high or critical detection alerts "
                "can become incidents"
            )
        )

    try:
        db.commit()
        db.refresh(item)
    except Exception:
        db.rollback()
        raise

    return item


# =====================================================
# GET INCIDENT DETAILS
# =====================================================

@router.get("/sla/summary")
def incident_sla_summary(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return priority-based operational target status for active incidents."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    incidents = db.query(Incident).order_by(Incident.created_at.asc()).all()
    counts = {"ON_TRACK": 0, "AT_RISK": 0, "BREACHED": 0, "COMPLETED": 0}
    rows = []
    for incident in incidents:
        sla = calculate_incident_sla(incident, now)
        counts[sla["state"]] += 1
        rows.append({
            "incident_id": incident.id,
            "incident_number": incident.incident_number,
            "priority": incident.priority,
            "status": incident.status,
            "assigned_to": incident.assigned_to,
            **sla,
        })
    return {
        "policy": SLA_TARGET_MINUTES,
        "counts": counts,
        "incidents": rows,
        "disclaimer": "Operational target estimates based on incident creation time and priority; configure these targets for your organisation.",
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):

    item = _detail(db, incident_id)

    return {
        "incident": item,
        "notes": item.notes,
        "actions": item.actions,
    }


# =====================================================
# UPDATE INCIDENT AND VALIDATE WORKFLOW
# =====================================================

@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse
)
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):

    item = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if not item:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided"
        )

    # -------------------------------------------------
    # Validate fields that cannot be NULL
    # -------------------------------------------------

    if "status" in changes and changes["status"] is None:
        raise HTTPException(
            status_code=422,
            detail="Incident status cannot be empty"
        )

    if "severity" in changes and changes["severity"] is None:
        raise HTTPException(
            status_code=422,
            detail="Incident severity cannot be empty"
        )

    if "priority" in changes and changes["priority"] is None:
        raise HTTPException(
            status_code=422,
            detail="Incident priority cannot be empty"
        )

    # -------------------------------------------------
    # Validate status transition
    # -------------------------------------------------

    old_status = item.status
    new_status = changes.get("status", old_status)

    status_changed = new_status != old_status

    if status_changed:

        allowed = ALLOWED_TRANSITIONS.get(old_status, set())

        if new_status not in allowed:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Invalid incident transition: "
                    f"{old_status} -> {new_status}. "
                    f"Allowed next statuses: {sorted(allowed)}"
                )
            )

    # -------------------------------------------------
    # Require explanation for RESOLVED and CLOSED
    # -------------------------------------------------

    if new_status in {"RESOLVED", "CLOSED"} and status_changed:

        resolution = changes.get("resolution")

        if (
            not isinstance(resolution, str)
            or not resolution.strip()
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"A meaningful explanation is required "
                    f"before changing an incident to {new_status}"
                )
            )

        changes["resolution"] = resolution.strip()

    # -------------------------------------------------
    # Validate resolution text if supplied
    # -------------------------------------------------

    if "resolution" in changes:

        resolution = changes["resolution"]

        if resolution is not None:

            if not isinstance(resolution, str):
                raise HTTPException(
                    status_code=422,
                    detail="Resolution must be text"
                )

            if not resolution.strip():
                raise HTTPException(
                    status_code=400,
                    detail="Resolution cannot contain only whitespace"
                )

            changes["resolution"] = resolution.strip()

    # -------------------------------------------------
    # Apply permitted updates and audit analyst assignment.
    # -------------------------------------------------

    previous_assignee = item.assigned_to
    if "assigned_to" in changes and changes["assigned_to"]:
        requested_assignee = changes["assigned_to"].strip()
        eligible_assignee = db.query(User).filter(
            User.username == requested_assignee,
            User.is_active.is_(True),
            User.role.in_(["admin", "analyst"]),
        ).first()
        if not eligible_assignee:
            raise HTTPException(
                status_code=422,
                detail="Assignee must be an active administrator or analyst username",
            )
        changes["assigned_to"] = eligible_assignee.username

    for key, value in changes.items():
        if key == "assigned_to" and isinstance(value, str):
            value = value.strip() or None
            changes[key] = value
        setattr(item, key, value)

    if "assigned_to" in changes and changes["assigned_to"] != previous_assignee:
        db.add(IncidentAction(
            incident_id=item.id,
            actor=user.username,
            action_type="ANALYST_ASSIGNED",
            details=f"Assignment changed from {previous_assignee or 'Unassigned'} to {changes['assigned_to'] or 'Unassigned'}",
            outcome="RECORDED",
        ))

    item.updated_at = datetime.now(timezone.utc).replace(
        tzinfo=None
    )

    # -------------------------------------------------
    # Automatically record status change
    # -------------------------------------------------

    if status_changed:

        _record_status_change(
            db=db,
            incident=item,
            old_status=old_status,
            new_status=new_status,
            username=user.username,
        )

    write_audit_log(
        db, actor=user, action="INCIDENT_UPDATED", target_type="incident",
        target_id=item.id, details=f"Updated fields: {', '.join(sorted(changes.keys()))}",
    )

    # -------------------------------------------------
    # Commit incident and history together
    # -------------------------------------------------

    try:
        db.commit()
        db.refresh(item)

    except Exception:
        db.rollback()
        raise

    return item


# =====================================================
# ADD INVESTIGATION NOTE
# =====================================================

@router.post("/{incident_id}/notes", status_code=201)
def add_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):

    _detail(db, incident_id)

    note = IncidentNote(
        incident_id=incident_id,
        author=user.username,
        note=payload.note,
    )

    db.add(note)
    write_audit_log(db, actor=user, action="INCIDENT_NOTE_ADDED", target_type="incident", target_id=incident_id, details="Analyst added an investigation note.")

    try:
        db.commit()
        db.refresh(note)

    except Exception:
        db.rollback()
        raise

    return note


# =====================================================
# ADD RESPONSE ACTION
# =====================================================

@router.post("/{incident_id}/actions", status_code=201)
def add_action(
    incident_id: int,
    payload: IncidentActionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin", "analyst")),
):

    _detail(db, incident_id)

    action = IncidentAction(
        incident_id=incident_id,
        actor=user.username,
        action_type=payload.action_type,
        details=payload.details,
        outcome=payload.outcome,
    )

    db.add(action)
    write_audit_log(db, actor=user, action="INCIDENT_RESPONSE_ACTION_ADDED", target_type="incident", target_id=incident_id, details=f"Action type: {payload.action_type}")

    try:
        db.commit()
        db.refresh(action)

    except Exception:
        db.rollback()
        raise

    return action


# =====================================================
# INCIDENT INVESTIGATION TIMELINE (PHASE 5)
# =====================================================
from app.services.incident_timeline import build_incident_timeline


@router.get("/{incident_id}/timeline")
def incident_timeline(
    incident_id: int,
    window_minutes: int = Query(30, ge=1, le=240),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return bounded correlated evidence and analyst activity for an incident."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return build_incident_timeline(db, incident, window_minutes=window_minutes)
