"""Guard: every (HTTP method, path) is defined once across siempl/web/routes*.py.

The app mounts routes_<name>.py routers before the legacy routes.py router and the
first match wins, so a second definition of the same route is silently dead code
(this is how 14 shadowed handlers accumulated in routes.py). Fail loudly instead.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

import siempl.web

_HTTP = {"get", "post", "put", "delete", "patch"}


def _registrations() -> dict[tuple[str, str], list[str]]:
    seen: dict[tuple[str, str], list[str]] = defaultdict(list)
    for path in sorted(Path(siempl.web.__file__).parent.glob("routes*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in _HTTP and dec.args
                        and isinstance(dec.args[0], ast.Constant)):
                    seen[(dec.func.attr.upper(), dec.args[0].value)].append(f"{path.name}:{node.name}")
    return seen


def test_no_route_is_defined_twice():
    dupes = {k: v for k, v in _registrations().items() if len(v) > 1}
    assert not dupes, f"duplicate route definitions (only the first is reachable): {dupes}"


def test_route_scan_finds_routes():
    # Guards the guard: if the scan matches nothing the test above proves nothing.
    assert len(_registrations()) > 50
