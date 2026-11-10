"""Static guardrails ensuring analyst-facing event routes stay authenticated.

These AST checks intentionally run without importing the FastAPI app, so they
remain usable in restricted review environments where optional auth packages
may not be installed.
"""
import ast
from pathlib import Path


ROUTER_PATH = Path(__file__).resolve().parents[1] / "app" / "routers" / "security_events.py"
PROTECTED_HANDLERS = {
    "get_security_statistics",
    "get_threat_activity",
    "get_security_events",
    "get_security_event",
    "update_security_event",
    "investigate_security_event",
}


def _depends_on_current_user(function: ast.FunctionDef) -> bool:
    for argument in function.args.args + function.args.kwonlyargs:
        default = None
        all_args = function.args.args + function.args.kwonlyargs
        defaults = [None] * (len(all_args) - len(function.args.defaults)) + list(function.args.defaults)
        if argument in all_args:
            default = defaults[all_args.index(argument)]
        if isinstance(default, ast.Call) and isinstance(default.func, ast.Name):
            if default.func.id == "Depends" and default.args:
                dependency = default.args[0]
                if isinstance(dependency, ast.Name) and dependency.id == "get_current_user":
                    return True
    return False


def test_all_analyst_event_routes_require_authenticated_user():
    tree = ast.parse(ROUTER_PATH.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = sorted(
        name for name in PROTECTED_HANDLERS
        if name not in functions or not _depends_on_current_user(functions[name])
    )
    assert not missing, f"Analyst-facing event routes missing get_current_user: {missing}"


def test_machine_ingestion_keeps_agent_key_gate():
    source = ROUTER_PATH.read_text(encoding="utf-8")
    assert 'alias="X-Agent-Key"' in source
    assert "hmac.compare_digest" in source
    assert "Invalid endpoint agent credentials" in source
