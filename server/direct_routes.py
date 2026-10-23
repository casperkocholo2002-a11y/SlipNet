#!/usr/bin/env python3

import copy
import json
import os
import re
import tempfile
import threading
from pathlib import Path

CONFIG_FILE = Path(os.environ.get(
    "SLIPNET_DIRECT_ROUTES_FILE",
    "/etc/slipnet-ea/direct-routes.json",
))
STATE_FILE = Path(os.environ.get(
    "SLIPNET_DIRECT_ROUTE_STATE_FILE",
    "/var/lib/slipnet-monitor/direct-route-state.json",
))
USER_FILE = Path(os.environ.get(
    "SLIPNET_DIRECT_USER_ROUTES_FILE",
    "/var/lib/slipnet-monitor/direct-user-routes.json",
))

_LOCK = threading.RLock()
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_USER_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def _atomic_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _load_json(path, default):
    try:
        with open(path, "r") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else copy.deepcopy(default)
    except FileNotFoundError:
        return copy.deepcopy(default)
    except Exception as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}")


def _validate_route(raw):
    if not isinstance(raw, dict):
        raise ValueError("Route must be an object")

    route_id = str(raw.get("id") or "").strip().lower()
    if not _ID_RE.fullmatch(route_id):
        raise ValueError("Invalid route id")

    label = str(raw.get("label") or route_id).strip()
    if not label or len(label) > 80:
        raise ValueError(f"Invalid label for {route_id}")

    provider = str(raw.get("provider") or "direct").strip().lower()
    if provider not in {"parspack", "arvan", "direct"}:
        raise ValueError(f"Unsupported provider for {route_id}")

    host = str(raw.get("host") or "").strip().lower().rstrip(".")
    if not _HOST_RE.fullmatch(host):
        raise ValueError(f"Invalid public host for {route_id}")

    inbound_tag = str(raw.get("inbound_tag") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", inbound_tag):
        raise ValueError(f"Invalid Xray inbound tag for {route_id}")

    try:
        port = int(raw.get("port", 443))
    except Exception:
        raise ValueError(f"Invalid port for {route_id}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port for {route_id}")

    path = str(raw.get("path") or "").strip()
    if not path.startswith("/") or len(path) < 9 or "?" in path or "#" in path:
        raise ValueError(f"Invalid public path for {route_id}")

    return {
        "id": route_id,
        "label": label,
        "provider": provider,
        "host": host,
        "inbound_tag": inbound_tag,
        "port": port,
        "path": path,
        "default_enabled": bool(raw.get("enabled", True)),
    }


def _definitions():
    raw = _load_json(CONFIG_FILE, {"version": 1, "routes": []})
    routes = raw.get("routes", [])
    if not isinstance(routes, list):
        raise RuntimeError("direct-routes.json routes must be a list")

    out = []
    seen = set()
    for item in routes:
        route = _validate_route(item)
        if route["id"] in seen:
            raise RuntimeError(f"Duplicate direct route: {route['id']}")
        seen.add(route["id"])
        out.append(route)
    return out


def _state():
    return _load_json(STATE_FILE, {"version": 1, "routes": {}})


def _users():
    return _load_json(USER_FILE, {"version": 1, "users": {}})


def list_routes(include_private=False):
    with _LOCK:
        state = _state().get("routes", {})
        result = []
        for route in _definitions():
            item = copy.deepcopy(route)
            item["enabled"] = bool(
                state.get(item["id"], {}).get("enabled", item["default_enabled"])
            )
            if not include_private:
                item.pop("path", None)
                item.pop("inbound_tag", None)
                item.pop("default_enabled", None)
            result.append(item)
        return result


def set_route_enabled(route_id, enabled):
    route_id = str(route_id or "").strip().lower()
    with _LOCK:
        known = {r["id"] for r in _definitions()}
        if route_id not in known:
            raise ValueError("Unknown direct route")
        state = _state()
        state.setdefault("routes", {}).setdefault(route_id, {})["enabled"] = bool(enabled)
        _atomic_json(STATE_FILE, state)
        return {"success": True, "route_id": route_id, "enabled": bool(enabled)}


def enabled_routes(include_private=True):
    return [r for r in list_routes(include_private=include_private) if r["enabled"]]


def assigned_route_ids(username):
    username = str(username or "").strip().lower()
    if not _USER_RE.fullmatch(username):
        raise ValueError("Invalid user name")

    with _LOCK:
        known = {r["id"] for r in _definitions()}
        raw = _users().get("users", {}).get(username, [])
        if not isinstance(raw, list):
            return []
        return [x for x in raw if x in known]


def user_route_ids(username):
    enabled = {r["id"] for r in enabled_routes(include_private=False)}
    return [x for x in assigned_route_ids(username) if x in enabled]


def routes_for_user(username):
    selected = set(user_route_ids(username))
    return [
        r for r in enabled_routes(include_private=True)
        if r["id"] in selected
    ]


def set_user_routes(username, route_ids):
    username = str(username or "").strip().lower()
    if not _USER_RE.fullmatch(username):
        raise ValueError("Invalid user name")
    if not isinstance(route_ids, list):
        raise ValueError("route_ids must be a list")

    route_ids = list(dict.fromkeys(str(x).strip().lower() for x in route_ids if str(x).strip()))
    with _LOCK:
        known = {r["id"] for r in _definitions()}
        unknown = [x for x in route_ids if x not in known]
        if unknown:
            raise ValueError("Unknown direct route: " + ", ".join(unknown))

        data = _users()
        data.setdefault("users", {})[username] = route_ids
        _atomic_json(USER_FILE, data)
        return {
            "success": True,
            "name": username,
            "route_ids": route_ids,
        }


def drop_user(username):
    username = str(username or "").strip().lower()
    with _LOCK:
        data = _users()
        users = data.setdefault("users", {})
        if username in users:
            users.pop(username, None)
            _atomic_json(USER_FILE, data)


def user_summary(username):
    selected = set(assigned_route_ids(username))
    routes = []
    for route in list_routes(include_private=False):
        item = copy.deepcopy(route)
        item["assigned"] = item["id"] in selected
        routes.append(item)
    return {
        "success": True,
        "name": str(username or "").strip().lower(),
        "routes": routes,
        "assigned_route_ids": [r["id"] for r in routes if r["assigned"]],
    }
