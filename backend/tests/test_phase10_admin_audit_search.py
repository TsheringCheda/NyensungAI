"""Phase 10 guardrails for admin access, audit logging and analyst search."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _functions(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_admin_user_management_and_audit_routes_are_admin_only():
    functions = _functions(ROOT / "app/routers/auth.py")
    for name in ("list_users", "update_user_access", "list_audit_logs"):
        assert name in functions
        source = ast.get_source_segment((ROOT / "app/routers/auth.py").read_text(encoding="utf-8"), functions[name])
        assert 'require_role("admin")' in source


def test_viewer_cannot_mutate_incidents_or_security_event_status():
    incident_functions = _functions(ROOT / "app/routers/incidents.py")
    for name in ("create_incident_from_event", "update_incident", "add_note", "add_action"):
        source = ast.get_source_segment((ROOT / "app/routers/incidents.py").read_text(encoding="utf-8"), incident_functions[name])
        assert 'require_role("admin", "analyst")' in source
    event_functions = _functions(ROOT / "app/routers/security_events.py")
    update_source = ast.get_source_segment((ROOT / "app/routers/security_events.py").read_text(encoding="utf-8"), event_functions["update_security_event"])
    assert 'current_user.role not in {"admin", "analyst"}' in update_source


def test_incident_search_supports_filters_and_bounded_pagination():
    functions = _functions(ROOT / "app/routers/incidents.py")
    source = ast.get_source_segment((ROOT / "app/routers/incidents.py").read_text(encoding="utf-8"), functions["search_incidents"])
    for expected in ("severity", "status", "priority", "assigned_to", "source_ip", "since", "until", "page_size"):
        assert expected in source
    assert "le=100" in source
    assert '"total": total' in source


def test_security_event_search_supports_risk_and_time_filters():
    source = (ROOT / "app/routers/security_events.py").read_text(encoding="utf-8")
    for expected in ("event_type", "username", "min_risk", "max_risk", "since", "until"):
        assert expected in source


def test_production_mode_disables_interactive_api_documentation():
    source = (ROOT / "app/main.py").read_text(encoding="utf-8")
    assert 'docs_url=None if IS_PRODUCTION else "/docs"' in source
    assert 'redoc_url=None if IS_PRODUCTION else "/redoc"' in source
    assert 'if IS_PRODUCTION' in source


def test_audit_writer_persists_actor_and_target_metadata():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app.models.audit_log import AuditLog
    from app.services.audit import write_audit_log

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    class Actor:
        id = 19
        username = "soc-admin"

    row = write_audit_log(
        session, actor=Actor(), action="INCIDENT_UPDATED",
        target_type="incident", target_id=88,
        details="Updated fields: status", source_ip="192.0.2.10",
    )
    session.commit()
    saved = session.query(AuditLog).one()
    assert saved.id == row.id
    assert saved.actor_user_id == 19
    assert saved.actor_username == "soc-admin"
    assert saved.target_id == "88"
    assert saved.action == "INCIDENT_UPDATED"
    session.close()
    engine.dispose()


def test_incident_assignment_requires_active_admin_or_analyst_account():
    functions = _functions(ROOT / "app/routers/incidents.py")
    source_text = (ROOT / "app/routers/incidents.py").read_text(encoding="utf-8")
    source = ast.get_source_segment(source_text, functions["update_incident"])
    assert 'User.is_active.is_(True)' in source
    assert 'User.role.in_(["admin", "analyst"])' in source
    assert "Assignee must be an active administrator or analyst username" in source
