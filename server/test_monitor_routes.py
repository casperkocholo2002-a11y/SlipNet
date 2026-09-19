import json
import os
import re
import shutil
import subprocess
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


class MonitorRouteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.artifact = Path(self.tmp.name) / "alice.slipnet"
        self.artifact.write_text("slipnet-enroll://test\n")
        self.calls = []

        self.saved = {
            "get_all_data": m.get_all_data,
            "subprocess_run": m.subprocess.run,
        }
        for name in (
            "list_users_with_activity",
            "list_users",
            "config_payload",
            "profile_artifact",
            "subscription_usage_for_token",
            "issue_enrollment_challenge",
            "redeem_enrollment",
            "complete_enrollment",
            "add_user",
            "delete_user",
            "update_user_limits",
            "reset_user_usage",
            "reissue_enrollment",
        ):
            self.saved[name] = getattr(m.vless_admin, name)

        m.get_all_data = lambda: {
            "timestamp": "test",
            "online_users": 0,
            "usage_total": 0,
            "users": {},
            "vless_users": [{"name": "alice", "enrollment_state": "unused"}],
        }
        m.vless_admin.list_users_with_activity = lambda: [
            {"name": "alice", "activity": [], "enrollment_state": "unused"}
        ]
        m.vless_admin.list_users = lambda: [
            {"name": "alice", "activity": [], "enrollment_state": "unused"}
        ]
        m.vless_admin.config_payload = lambda name: {
            "success": True,
            "name": name,
            "bundle": "slipnet-enroll://test",
            "uri": "slipnet-enroll://test",
            "filename": f"{name}.slipnet",
        }
        m.vless_admin.profile_artifact = lambda name: (
            self.artifact,
            {"success": True, "filename": f"{name}.slipnet"},
        )
        m.vless_admin.subscription_usage_for_token = lambda token: {
            "success": True, "name": "alice", "total": 123
        }
        m.vless_admin.issue_enrollment_challenge = lambda *args: {
            "success": True, "challenge": "x" * 43
        }
        m.vless_admin.redeem_enrollment = lambda *args: {
            "success": True, "bundle": "slipnet://A\nslipnet://B\n"
        }
        m.vless_admin.complete_enrollment = lambda *args: {
            "success": True, "enrollment_state": "redeemed"
        }

        def record(name):
            def fn(*args, **kwargs):
                self.calls.append((name, args, kwargs))
                return {"success": True, "name": args[0] if args else "alice"}
            return fn

        m.vless_admin.add_user = record("add")
        m.vless_admin.delete_user = record("delete")
        m.vless_admin.update_user_limits = record("limits")
        m.vless_admin.reset_user_usage = record("reset_usage")
        m.vless_admin.reissue_enrollment = record("reissue")

        class Proc:
            returncode = 0
            stdout = b"PNGDATA"
            stderr = b""
        m.subprocess.run = lambda *args, **kwargs: Proc()

        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        m.get_all_data = self.saved["get_all_data"]
        m.subprocess.run = self.saved["subprocess_run"]
        for name, value in self.saved.items():
            if name not in ("get_all_data", "subprocess_run"):
                setattr(m.vless_admin, name, value)
        self.tmp.cleanup()

    def request(self, path, method="GET", body=None, requested_with=True):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if requested_with:
            headers["X-Requested-With"] = "SlipNetMonitor"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def json_request(self, path, method="GET", body=None, requested_with=True):
        status, _, raw = self.request(path, method, body, requested_with)
        return status, json.loads(raw.decode())

    def test_read_routes(self):
        status, data = self.json_request("/api/data")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["vless_users"]), 1)

        status, data = self.json_request("/api/vless/users")
        self.assertEqual(status, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["users"][0]["name"], "alice")

        status, data = self.json_request("/api/vless/config?user=alice")
        self.assertEqual(status, 200)
        self.assertEqual(data["bundle"], "slipnet-enroll://test")

        status, headers, raw = self.request("/api/vless/download?user=alice")
        self.assertEqual(status, 200)
        self.assertIn("alice.slipnet", headers.get("Content-Disposition", ""))
        self.assertEqual(raw, b"slipnet-enroll://test\n")

        status, headers, raw = self.request("/api/vless/qr?user=alice")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "image/png")
        self.assertEqual(raw, b"PNGDATA")

        req = urllib.request.Request(
            self.base + "/api/subscription/usage",
            headers={"X-SlipNet-Subscription": "token"},
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read())
        self.assertEqual(data["total"], 123)

    def test_get_all_data_exposes_degraded_and_total_failure_states(self):
        old_active = m.get_active_users
        old_tunnels = m.read_tunnel_stats
        old_activity = m.vless_admin.list_users_with_activity
        old_list = m.vless_admin.list_users
        try:
            m.get_active_users = lambda: {}
            m.read_tunnel_stats = lambda: []

            def activity_fail():
                raise RuntimeError("activity down")
            m.vless_admin.list_users_with_activity = activity_fail
            m.vless_admin.list_users = lambda: [{
                "name": "alice",
                "online": False,
                "last_activity": None,
                "uplink": 10,
                "downlink": 20,
                "total": 30,
            }]
            data = self.saved["get_all_data"]()
            self.assertTrue(data["vless_users_degraded"])
            self.assertIn("Recent activity unavailable", data["vless_users_error"])
            self.assertEqual(len(data["vless_users"]), 1)

            def users_fail():
                raise RuntimeError("users down")
            m.vless_admin.list_users = users_fail
            data = self.saved["get_all_data"]()
            self.assertTrue(data["vless_users_degraded"])
            self.assertIn("VLESS user data unavailable", data["vless_users_error"])
            self.assertEqual(data["vless_users"], [])
        finally:
            m.get_active_users = old_active
            m.read_tunnel_stats = old_tunnels
            m.vless_admin.list_users_with_activity = old_activity
            m.vless_admin.list_users = old_list

    def test_data_route_returns_json_500_instead_of_dropping_connection(self):
        old = m.get_all_data
        try:
            def fail():
                raise RuntimeError("synthetic dashboard failure")
            m.get_all_data = fail
            status, data = self.json_request("/api/data")
            self.assertEqual(status, 500)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"], "Monitor data unavailable")
        finally:
            m.get_all_data = old

    def test_vless_users_activity_fallback_and_total_failure(self):
        old_activity = m.vless_admin.list_users_with_activity
        old_list = m.vless_admin.list_users
        try:
            def activity_fail():
                raise RuntimeError("activity unavailable")
            m.vless_admin.list_users_with_activity = activity_fail
            status, data = self.json_request("/api/vless/users")
            self.assertEqual(status, 200)
            self.assertTrue(data["success"])
            self.assertTrue(data["degraded_activity"])
            self.assertEqual(data["users"][0]["name"], "alice")

            def list_fail():
                raise RuntimeError("users unavailable")
            m.vless_admin.list_users = list_fail
            status, data = self.json_request("/api/vless/users")
            self.assertEqual(status, 500)
            self.assertFalse(data["success"])
        finally:
            m.vless_admin.list_users_with_activity = old_activity
            m.vless_admin.list_users = old_list

    def test_admin_mutation_routes_and_csrf_header(self):
        cases = [
            ("/api/vless/add", {"name": "alice", "duration_days": 30, "quota_bytes": 0}, "add"),
            ("/api/vless/delete", {"name": "alice"}, "delete"),
            ("/api/vless/limits", {"name": "alice", "duration_days": 30, "quota_bytes": 10}, "limits"),
            ("/api/vless/reset-usage", {"name": "alice"}, "reset_usage"),
            ("/api/vless/reissue", {"name": "alice"}, "reissue"),
        ]
        for path, body, expected in cases:
            with self.subTest(path=path):
                self.calls.clear()
                status, data = self.json_request(path, "POST", body)
                self.assertEqual(status, 200)
                self.assertTrue(data["success"])
                self.assertEqual(self.calls[0][0], expected)

                status, data = self.json_request(
                    path, "POST", body, requested_with=False
                )
                self.assertEqual(status, 403)
                self.assertFalse(data["success"])

        status, data = self.json_request(
            "/api/vless/password",
            "POST",
            {"name": "alice", "password": "abcdef"},
        )
        self.assertEqual(status, 404)
        self.assertFalse(data["success"])

    def test_public_enrollment_routes_and_status_mapping(self):
        status, data = self.json_request(
            "/api/enrollment/challenge",
            "POST",
            {"token": "t", "device_id": "d", "public_key": "k"},
            requested_with=False,
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["success"])

        status, data = self.json_request(
            "/api/enrollment/redeem",
            "POST",
            {
                "token": "t", "device_id": "d", "public_key": "k",
                "challenge": "c", "signature": "s",
            },
            requested_with=False,
        )
        self.assertEqual(status, 200)
        self.assertIn("slipnet://A", data["bundle"])

        status, data = self.json_request(
            "/api/enrollment/complete",
            "POST",
            {
                "token": "t", "device_id": "d", "public_key": "k",
                "challenge": "c", "signature": "s",
            },
            requested_with=False,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["enrollment_state"], "redeemed")

    def test_public_enrollment_error_status_mapping(self):
        old = m.vless_admin.issue_enrollment_challenge
        cases = [
            (m.vless_admin.EnrollmentAlreadyUsedError("used"), 409),
            (PermissionError("denied"), 403),
            (ValueError("bad"), 400),
            (RuntimeError("down"), 503),
        ]
        try:
            for error, expected in cases:
                with self.subTest(error=type(error).__name__):
                    def fail(*args, _error=error, **kwargs):
                        raise _error
                    m.vless_admin.issue_enrollment_challenge = fail
                    status, data = self.json_request(
                        "/api/enrollment/challenge",
                        "POST",
                        {"token": "t", "device_id": "d", "public_key": "k"},
                        requested_with=False,
                    )
                    self.assertEqual(status, expected)
                    self.assertFalse(data["success"])
        finally:
            m.vless_admin.issue_enrollment_challenge = old

    @unittest.skipUnless(shutil.which("node"), "node is required for embedded JS syntax gate")
    def test_all_embedded_javascript_parses(self):
        scripts = re.findall(r"<script>(.*?)</script>", m.HTML, flags=re.S | re.I)
        self.assertGreaterEqual(len(scripts), 1)
        root = Path(self.tmp.name) / "js"
        root.mkdir()
        for index, script in enumerate(scripts, 1):
            path = root / f"{index}.js"
            path.write_text(script)
            proc = subprocess.run(
                ["node", "--check", str(path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
