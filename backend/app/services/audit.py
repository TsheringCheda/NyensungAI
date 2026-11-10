from app.models.audit_log import AuditLog


def write_audit_log(
    db,
    *,
    actor,
    action: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: str | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    """Add an audit record to the caller's transaction; caller commits it."""
    record = AuditLog(
        actor_user_id=getattr(actor, "id", None),
        actor_username=getattr(actor, "username", "system"),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=(details or "")[:4000] or None,
        source_ip=source_ip,
    )
    db.add(record)
    return record
