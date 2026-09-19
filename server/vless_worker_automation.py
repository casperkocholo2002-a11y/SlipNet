#!/usr/bin/env python3

import base64
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path


def _required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


ORIGIN_HOST = _required_env("SLIPNET_WORKER_ORIGIN_HOST")
ENROLLMENT_ORIGIN_HOST = os.environ.get(
    "SLIPNET_ENROLLMENT_ORIGIN_HOST",
    "monitor.cspf.shop",
).strip()
if not ENROLLMENT_ORIGIN_HOST:
    raise RuntimeError("SLIPNET_ENROLLMENT_ORIGIN_HOST is required")

PRIMARY = {
    "account_id": _required_env("SLIPNET_CF_PRIMARY_ACCOUNT_ID"),
    "token_file": os.environ.get("SLIPNET_CF_PRIMARY_TOKEN_FILE", "/etc/slipnet-ea/cloudflare-primary.token"),
    "subdomain": _required_env("SLIPNET_CF_PRIMARY_SUBDOMAIN"),
    "map_file": os.environ.get("SLIPNET_CF_PRIMARY_MAP_FILE", "/var/lib/slipnet-ea/vless-worker-map.tsv"),
    "prefix": os.environ.get("SLIPNET_CF_PRIMARY_PREFIX", "asset"),
}

BACKUP = {
    "account_id": _required_env("SLIPNET_CF_BACKUP_ACCOUNT_ID"),
    "token_file": os.environ.get("SLIPNET_CF_BACKUP_TOKEN_FILE", "/etc/slipnet-ea/cloudflare-backup.token"),
    "subdomain": _required_env("SLIPNET_CF_BACKUP_SUBDOMAIN"),
    "map_file": os.environ.get("SLIPNET_CF_BACKUP_MAP_FILE", "/var/lib/slipnet-ea/vless-worker-backup-map.tsv"),
    "prefix": os.environ.get("SLIPNET_CF_BACKUP_PREFIX", "cdn"),
}



WORKER_JS = """
const ORIGIN_HOST = __ORIGIN_HOST__;
const ENROLLMENT_ORIGIN_HOST = __ENROLLMENT_ORIGIN_HOST__;
const ENROLLMENT_PATHS = new Set([
  "/api/enrollment/challenge",
  "/api/enrollment/redeem"
]);

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "POST" && ENROLLMENT_PATHS.has(url.pathname)) {
      url.protocol = "https:";
      url.hostname = ENROLLMENT_ORIGIN_HOST;
      url.port = "443";
      return fetch(url.toString(), request);
    }

    const upgrade = request.headers.get("Upgrade");

    if (!upgrade || upgrade.toLowerCase() !== "websocket") {
      return new Response("Not Found", {
        status: 404,
        headers: {
          "Cache-Control": "no-store"
        }
      });
    }

    url.protocol = "https:";
    url.hostname = ORIGIN_HOST;
    url.port = "443";

    return fetch(url.toString(), request);
  }
};
""".replace("__ORIGIN_HOST__", json.dumps(ORIGIN_HOST)).replace(
    "__ENROLLMENT_ORIGIN_HOST__",
    json.dumps(ENROLLMENT_ORIGIN_HOST),
)


def _run(args, timeout=45, check=True):
    p = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if check and p.returncode != 0:
        msg = (
            p.stderr
            or p.stdout
            or f"command failed: {p.returncode}"
        ).strip()

        raise RuntimeError(msg[-1200:])

    return p


def _token(spec):
    token = Path(spec["token_file"]).read_text().strip()

    if not token:
        raise RuntimeError(
            f"Empty Cloudflare token file: {spec['token_file']}"
        )

    return token


def _curl_json(spec, method, url, extra=None, timeout=45):
    token = _token(spec)

    args = [
        "curl",
        "-4",
        "--retry", "4",
        "--retry-delay", "1",
        "--retry-all-errors",
        "-sS",
        "-X", method,
        "-H", f"Authorization: Bearer {token}",
    ]

    if extra:
        args.extend(extra)

    args.append(url)

    p = _run(
        args,
        timeout=timeout,
    )

    try:
        data = json.loads(p.stdout)

    except Exception:
        raise RuntimeError(
            "Cloudflare returned a non-JSON response"
        )

    if not data.get("success"):
        errors = data.get("errors") or []

        message = "; ".join(
            str(
                item.get("message")
                or item.get("code")
                or item
            )
            for item in errors
        )

        if not message:
            message = "Cloudflare API request failed"

        raise RuntimeError(message[:1000])

    return data


def _read_map(path):
    rows = {}

    p = Path(path)

    if not p.exists():
        return rows

    for raw in p.read_text().splitlines():
        raw = raw.strip()

        if not raw:
            continue

        if raw.lower().startswith("user\t"):
            continue

        parts = raw.split("\t")

        if len(parts) < 3:
            continue

        user, worker, hostname = parts[:3]

        rows[user.lower()] = {
            "user": user,
            "worker": worker,
            "hostname": hostname,
        }

    return rows


def _write_map(path, rows):
    p = Path(path)

    lines = [
        "user\tworker\thostname"
    ]

    for item in rows.values():
        lines.append(
            f"{item['user']}\t"
            f"{item['worker']}\t"
            f"{item['hostname']}"
        )

    fd, tmp = tempfile.mkstemp(
        prefix=f".{p.name}.",
        dir=str(p.parent),
    )

    try:
        with os.fdopen(fd, "w") as f:
            f.write(
                "\n".join(lines) + "\n"
            )
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, 0o600)
        os.replace(tmp, p)

    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _snapshot(path):
    p = Path(path)

    if not p.exists():
        return None

    return p.read_bytes()


def _restore(path, content):
    p = Path(path)

    if content is None:
        try:
            p.unlink()
        except FileNotFoundError:
            pass

        return

    fd, tmp = tempfile.mkstemp(
        prefix=f".{p.name}.restore.",
        dir=str(p.parent),
    )

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, 0o600)
        os.replace(tmp, p)

    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _random_worker_name(prefix):
    return (
        f"{prefix}-"
        f"{secrets.token_hex(5)}"
    )


def _upload_worker(spec, worker_name):
    account = spec["account_id"]

    url = (
        "https://api.cloudflare.com/client/v4/"
        f"accounts/{account}/workers/scripts/"
        f"{worker_name}"
    )

    fd, js_path = tempfile.mkstemp(
        prefix="slipnet-worker-",
        suffix=".mjs",
    )

    try:
        with os.fdopen(fd, "w") as f:
            f.write(WORKER_JS)
            f.flush()
            os.fsync(f.fileno())

        extra = [
            "-F",
            (
                'metadata={'
                '"main_module":"worker.mjs",'
                '"compatibility_date":"2026-09-11"'
                '};type=application/json'
            ),
            "-F",
            (
                f"worker.mjs=@{js_path};"
                "filename=worker.mjs;"
                "type=application/javascript+module"
            ),
        ]

        _curl_json(
            spec,
            "PUT",
            url,
            extra=extra,
        )

    finally:
        try:
            os.unlink(js_path)
        except FileNotFoundError:
            pass

    subdomain_url = (
        "https://api.cloudflare.com/client/v4/"
        f"accounts/{account}/workers/scripts/"
        f"{worker_name}/subdomain"
    )

    _curl_json(
        spec,
        "POST",
        subdomain_url,
        extra=[
            "-H",
            "Content-Type: application/json",
            "--data",
            (
                '{"enabled":true,'
                '"previews_enabled":false}'
            ),
        ],
    )


def _delete_worker(spec, worker_name):
    account = spec["account_id"]
    token = _token(spec)

    url = (
        "https://api.cloudflare.com/client/v4/"
        f"accounts/{account}/workers/scripts/"
        f"{worker_name}"
    )

    args = [
        "curl",
        "-4",
        "--retry", "4",
        "--retry-delay", "1",
        "--retry-all-errors",
        "-sS",
        "-X", "DELETE",
        "-H",
        f"Authorization: Bearer {token}",
        url,
    ]

    p = _run(
        args,
        timeout=45,
        check=False,
    )

    if not p.stdout.strip():
        if p.returncode == 0:
            return

        msg = (
            p.stderr
            or "Worker delete failed"
        ).strip()

        raise RuntimeError(msg[-1000:])

    try:
        data = json.loads(p.stdout)

    except Exception:
        if p.returncode == 0:
            return

        raise RuntimeError(
            "Cloudflare returned non-JSON on delete"
        )

    if data.get("success"):
        return

    errors = data.get("errors") or []

    codes = {
        str(item.get("code"))
        for item in errors
    }

    # Already missing is harmless during cleanup.
    if "10090" in codes or "10007" in codes:
        return

    message = "; ".join(
        str(
            item.get("message")
            or item.get("code")
            or item
        )
        for item in errors
    )

    if not message:
        message = "Worker delete failed"

    raise RuntimeError(
        message[:1000]
    )


def _ws_test(hostname, ws_path):
    import time

    last_status = "no HTTP status"

    # New workers.dev hostnames can take a few seconds
    # before every Cloudflare edge serves the new Worker.
    for attempt in range(1, 11):
        fd, header_path = tempfile.mkstemp(
            prefix="slipnet-worker-ws-",
            suffix=".headers",
        )

        os.close(fd)

        try:
            ws_key = base64.b64encode(
                os.urandom(16)
            ).decode()

            args = [
                "curl",
                "-4",
                "--http1.1",
                "--max-time", "6",
                "-sS",
                "-o", "/dev/null",
                "-D", header_path,
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Version: 13",
                "-H",
                f"Sec-WebSocket-Key: {ws_key}",
                f"https://{hostname}{ws_path}",
            ]

            _run(
                args,
                timeout=10,
                check=False,
            )

            try:
                lines = (
                    Path(header_path)
                    .read_text(errors="replace")
                    .splitlines()
                )

                if lines:
                    last_status = lines[0]

            except Exception:
                pass

            if " 101 " in f" {last_status} ":
                return

        finally:
            try:
                os.unlink(header_path)
            except FileNotFoundError:
                pass

        if attempt < 10:
            time.sleep(4)

    raise RuntimeError(
        "WebSocket validation failed for "
        f"{hostname} after 10 attempts: "
        f"{last_status}"
    )


def _create_one(spec, ws_path):
    worker = _random_worker_name(
        spec["prefix"]
    )

    hostname = (
        f"{worker}."
        f"{spec['subdomain']}."
        "workers.dev"
    )

    _upload_worker(
        spec,
        worker,
    )

    try:
        _ws_test(
            hostname,
            ws_path,
        )

    except Exception:
        try:
            _delete_worker(
                spec,
                worker,
            )
        except Exception:
            pass

        raise

    return {
        "worker": worker,
        "hostname": hostname,
    }


def primary_host(user):
    item = _read_map(
        PRIMARY["map_file"]
    ).get(
        (user or "").lower()
    )

    if not item:
        return None

    return item["hostname"]


def backup_host(user):
    item = _read_map(
        BACKUP["map_file"]
    ).get(
        (user or "").lower()
    )

    if not item:
        return None

    return item["hostname"]


def refresh_pair(user, ws_path):
    key = (user or "").lower()
    refreshed = {}

    for label, spec in (("primary", PRIMARY), ("backup", BACKUP)):
        item = _read_map(spec["map_file"]).get(key)
        if not item:
            continue

        _upload_worker(spec, item["worker"])
        _ws_test(item["hostname"], ws_path)
        refreshed[label] = item["hostname"]

    if not refreshed:
        raise RuntimeError(
            f"No Worker mapping exists for {user}"
        )

    return refreshed


def create_pair(user, ws_path):
    key = user.lower()

    if key in _read_map(
        PRIMARY["map_file"]
    ):
        raise RuntimeError(
            "Primary Worker mapping already "
            f"exists for {user}"
        )

    if key in _read_map(
        BACKUP["map_file"]
    ):
        raise RuntimeError(
            "Backup Worker mapping already "
            f"exists for {user}"
        )

    primary = None
    backup = None

    primary_snapshot = _snapshot(
        PRIMARY["map_file"]
    )

    backup_snapshot = _snapshot(
        BACKUP["map_file"]
    )

    try:
        primary = _create_one(
            PRIMARY,
            ws_path,
        )

        backup = _create_one(
            BACKUP,
            ws_path,
        )

        primary_rows = _read_map(
            PRIMARY["map_file"]
        )

        primary_rows[key] = {
            "user": user,
            "worker": primary["worker"],
            "hostname": primary["hostname"],
        }

        _write_map(
            PRIMARY["map_file"],
            primary_rows,
        )

        backup_rows = _read_map(
            BACKUP["map_file"]
        )

        backup_rows[key] = {
            "user": user,
            "worker": backup["worker"],
            "hostname": backup["hostname"],
        }

        _write_map(
            BACKUP["map_file"],
            backup_rows,
        )

        return {
            "primary": primary["hostname"],
            "backup": backup["hostname"],
        }

    except Exception:
        if backup:
            try:
                _delete_worker(
                    BACKUP,
                    backup["worker"],
                )
            except Exception:
                pass

        if primary:
            try:
                _delete_worker(
                    PRIMARY,
                    primary["worker"],
                )
            except Exception:
                pass

        try:
            _restore(
                PRIMARY["map_file"],
                primary_snapshot,
            )
        except Exception:
            pass

        try:
            _restore(
                BACKUP["map_file"],
                backup_snapshot,
            )
        except Exception:
            pass

        raise


def _delete_mapped(spec, user):
    rows = _read_map(
        spec["map_file"]
    )

    key = user.lower()

    item = rows.get(key)

    if not item:
        return None

    _delete_worker(
        spec,
        item["worker"],
    )

    rows.pop(
        key,
        None,
    )

    _write_map(
        spec["map_file"],
        rows,
    )

    return item["hostname"]


def delete_pair(user):
    warnings = []

    for label, spec in (
        ("primary", PRIMARY),
        ("backup", BACKUP),
    ):
        try:
            _delete_mapped(
                spec,
                user,
            )

        except Exception as e:
            warnings.append(
                f"{label}: {e}"
            )

    return warnings
