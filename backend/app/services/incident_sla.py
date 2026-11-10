from datetime import datetime, timedelta

# Operational response targets are defaults and should be configured per organisation.
SLA_TARGET_MINUTES = {"P1": 60, "P2": 240, "P3": 1440, "P4": 4320}


def calculate_incident_sla(incident, now: datetime) -> dict:
    created = incident.created_at
    if created.tzinfo is not None:
        created = created.replace(tzinfo=None)
    target_minutes = SLA_TARGET_MINUTES.get(incident.priority, 1440)
    due_at = created + timedelta(minutes=target_minutes)
    completed = incident.status in {"RESOLVED", "CLOSED"}
    elapsed = max(0, int((now - created).total_seconds() // 60))
    remaining = int((due_at - now).total_seconds() // 60)
    if completed:
        state = "COMPLETED"
    elif remaining < 0:
        state = "BREACHED"
    elif remaining <= max(15, int(target_minutes * 0.2)):
        state = "AT_RISK"
    else:
        state = "ON_TRACK"
    return {
        "target_minutes": target_minutes,
        "due_at": due_at.isoformat(),
        "elapsed_minutes": elapsed,
        "remaining_minutes": max(0, remaining),
        "state": state,
    }
