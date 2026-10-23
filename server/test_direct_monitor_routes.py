import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

os.environ.setdefault("SLIPNET_MONITOR_PASSWORD", "test-only-password")
os.environ.setdefault("SLIPNET_VLESS_PUBLIC_HOST", "example.test")
os.environ.setdefault("SLIPNET_WORKER_ORIGIN_HOST", "origin.example.test")
os.environ.setdefault("SLIPNET_CF_PRIMARY_ACCOUNT_ID", "primary-test")
os.environ.setdefault("SLIPNET_CF_PRIMARY_SUBDOMAIN", "primary.workers.dev")
os.environ.setdefault("SLIPNET_CF_BACKUP_ACCOUNT_ID", "backup-test")
os.environ.setdefault("SLIPNET_CF_BACKUP_SUBDOMAIN", "backup.workers.dev")

import slipnet_monitor as m


class _Handler(m.Handler):
    def check_auth(self):
        return True


class DirectMonitorRoutesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.artifact = Path(self.tmp.name) / "alice.direct.slipnet"
        self.artifact.write_text("slipnet://DIRECT\n")
        self.calls = []
        names = (
            "list_direct_routes",
            "direct_route_summary",
            "direct_config_payload",
            "direct_profile_artifact",
            "set_direct_routes",
            "set_direct_route_enabled",
        )
        self.saved = {name: getattr(m.vless_admin, name) for name in names}

        m.vless_admin.list_direct_routes = lambda: {
            "success": True,
            "routes": [{"id": "parspack-direct", "enabled": True}],
        }
        m.vless_admin.direct_route_summary = lambda name: {
            "success": True,
            "name": name,
            "routes": [{"id": "parspack-direct", "enabled": True, "assigned": True}],
            "assigned_route_ids": ["parspack-direct"],
        }
        m.vless_admin.direct_config_payload = lambda name: {
            "success": True,
            "name": name,
            "bundle": "slipnet://DIRECT\n",
            "filename": f"{name}.direct.slipnet",
        }
        m.vless_admin.direct_profile_artifact = lambda name: (
            self.artifact,
            {"success": True, "filename": f"{name}.direct.slipnet"},
        )

        def record(label):
            def fn(*args, **kwargs):
                self.calls.append((label, args, kwargs))
                return {"success": True}
            return fn

        m.vless_admin.set_direct_routes = record("user-routes")
        m.vless_admin.set_direct_route_enabled = record("route-state")

        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        for name, value in self.saved.items():
            setattr(m.vless_admin, name, value)
        self.tmp.cleanup()

    def request(self, path, method="GET", body=None, csrf=True):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-Requested-With"] = "SlipNetMonitor"
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_direct_read_and_download_routes(self):
        status, _, raw = self.request("/api/direct/routes")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["routes"][0]["id"], "parspack-direct")

        status, _, raw = self.request("/api/direct/routes?user=alice")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(raw)["assigned_route_ids"], ["parspack-direct"]
        )

        status, _, raw = self.request("/api/direct/config?user=alice")
        self.assertEqual(status, 200)
        self.assertIn("slipnet://DIRECT", json.loads(raw)["bundle"])

        status, headers, raw = self.request("/api/direct/download?user=alice")
        self.assertEqual(status, 200)
        self.assertIn("alice.direct.slipnet", headers["Content-Disposition"])
        self.assertEqual(raw, b"slipnet://DIRECT\n")

    def test_direct_mutations_and_csrf(self):
        status, _, raw = self.request(
            "/api/direct/user-routes",
            "POST",
            {"name": "alice", "route_ids": ["parspack-direct"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.calls[-1][0], "user-routes")

        status, _, raw = self.request(
            "/api/direct/route-state",
            "POST",
            {"route_id": "parspack-direct", "enabled": False},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.calls[-1][0], "route-state")

        status, _, raw = self.request(
            "/api/direct/route-state",
            "POST",
            {"route_id": "parspack-direct", "enabled": False},
            csrf=False,
        )
        self.assertEqual(status, 403)
        self.assertFalse(json.loads(raw)["success"])


if __name__ == "__main__":
    unittest.main()
