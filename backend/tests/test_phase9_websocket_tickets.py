"""Phase 9 tests for one-time WebSocket authentication tickets."""
import ast
from pathlib import Path

from app.services.realtime import WebSocketTicketStore


def test_ticket_is_single_use_and_bound_to_user_and_jti():
    store = WebSocketTicketStore(ttl_seconds=30)
    ticket = store.issue(42, "token-jti-abc")
    assert store.consume(ticket) == (42, "token-jti-abc")
    assert store.consume(ticket) is None


def test_expired_ticket_is_rejected(monkeypatch):
    import app.services.realtime as realtime

    clock = {"now": 100.0}
    monkeypatch.setattr(realtime.time, "monotonic", lambda: clock["now"])
    store = WebSocketTicketStore(ttl_seconds=5)
    ticket = store.issue(7, "jti")
    clock["now"] = 106.0
    assert store.consume(ticket) is None


def test_websocket_route_uses_ticket_not_jwt_query_parameter():
    router_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "security_events.py"
    source = router_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    websocket_functions = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "security_events_websocket"
    ]
    assert len(websocket_functions) == 1
    arguments = {arg.arg for arg in websocket_functions[0].args.args}
    assert "ticket" in arguments
    assert "token" not in arguments
    assert "websocket_tickets.consume(ticket)" in source
    assert "4403" in source


def test_ticket_endpoint_is_protected_by_bearer_dependency():
    auth_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "auth.py"
    source = auth_path.read_text(encoding="utf-8")
    assert '@router.post("/ws-ticket")' in source
    assert "credentials: HTTPAuthorizationCredentials = Depends(security)" in source
    assert "websocket_tickets.issue(current_user.id, token_jti)" in source
