import base64
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SLIPNET_MONITOR_PASSWORD", "test-only-password")
os.environ.setdefault("SLIPNET_VLESS_PUBLIC_HOST", "example.test")
os.environ.setdefault("SLIPNET_WORKER_ORIGIN_HOST", "origin.example.test")
os.environ.setdefault("SLIPNET_CF_PRIMARY_ACCOUNT_ID", "primary-test")
os.environ.setdefault("SLIPNET_CF_PRIMARY_SUBDOMAIN", "primary.workers.dev")
os.environ.setdefault("SLIPNET_CF_BACKUP_ACCOUNT_ID", "backup-test")
os.environ.setdefault("SLIPNET_CF_BACKUP_SUBDOMAIN", "backup.workers.dev")

import direct_routes as dr
import vless_admin as v


UUID_OLD = "11111111-2222-3333-4444-555555555555"
UUID_NEW = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def route_defs():
    return {
        "version": 1,
        "routes": [
            {
                "id": "parspack-direct",
                "label": "ParsPack Direct",
                "provider": "parspack",
                "enabled": True,
                "host": "pp.example.com",
                "port": 443,
                "path": "/relay/parspack-test",
                "inbound_tag": "vless-parspack-direct",
            },
            {
                "id": "arvan-direct",
                "label": "Arvan Direct",
                "provider": "arvan",
                "enabled": True,
                "host": "ar.example.com",
                "port": 443,
                "path": "/relay/arvan-test",
                "inbound_tag": "vless-arvan-direct",
            },
        ],
    }


def xray_cfg(uuid=UUID_OLD, direct_pp=False, direct_ar=False):
    user = {"id": uuid, "email": "alice"}
    return {
        "inbounds": [
            {
                "tag": v.TAG,
                "protocol": "vless",
                "settings": {"clients": [copy.deepcopy(user)]},
            },
            {
                "tag": "vless-parspack-direct",
                "protocol": "vless",
                "settings": {
                    "clients": [copy.deepcopy(user)] if direct_pp else []
                },
            },
            {
                "tag": "vless-arvan-direct",
                "protocol": "vless",
                "settings": {
                    "clients": [copy.deepcopy(user)] if direct_ar else []
                },
            },
        ]
    }


class DirectRouteRegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        dr.CONFIG_FILE = root / "routes.json"
        dr.STATE_FILE = root / "state.json"
        dr.USER_FILE = root / "users.json"
        dr.CONFIG_FILE.write_text(json.dumps(route_defs()))

    def tearDown(self):
        self.tmp.cleanup()

    def test_assignment_is_explicit_and_global_disable_preserves_assignment(self):
        self.assertEqual(dr.assigned_route_ids("alice"), [])
        self.assertEqual(dr.user_route_ids("alice"), [])

        dr.set_user_routes("alice", ["arvan-direct"])
        self.assertEqual(dr.assigned_route_ids("alice"), ["arvan-direct"])
        self.assertEqual(dr.user_route_ids("alice"), ["arvan-direct"])

        dr.set_route_enabled("arvan-direct", False)
        self.assertEqual(dr.assigned_route_ids("alice"), ["arvan-direct"])
        self.assertEqual(dr.user_route_ids("alice"), [])

        dr.set_route_enabled("arvan-direct", True)
        self.assertEqual(dr.user_route_ids("alice"), ["arvan-direct"])

    def test_private_xray_and_path_fields_are_not_exposed(self):
        public = dr.list_routes(include_private=False)[0]
        self.assertNotIn("path", public)
        self.assertNotIn("inbound_tag", public)

        private = dr.list_routes(include_private=True)[0]
        self.assertEqual(private["path"], "/relay/parspack-test")
        self.assertEqual(private["inbound_tag"], "vless-parspack-direct")

    def test_rejects_unknown_user_route(self):
        with self.assertRaises(ValueError):
            dr.set_user_routes("alice", ["does-not-exist"])


class DirectXrayEnforcementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        dr.CONFIG_FILE = root / "routes.json"
        dr.STATE_FILE = root / "state.json"
        dr.USER_FILE = root / "users.json"
        dr.CONFIG_FILE.write_text(json.dumps(route_defs()))

        self.cfg = xray_cfg()
        self.runtime = []

        self.saved = {
            "load": v._load,
            "get_client": v._get_client,
            "persist": v._persist,
            "validate": v._validate_config,
            "runtime_add": v._dx_runtime_add,
            "runtime_remove": v._dx_runtime_remove,
            "registry": v._v30_registry_item,
            "mkdirs": v._align_mkdirs,
            "profile_dir": v._ALIGN_PROFILE_DIR,
            "base_replace": v._dx_base_replace_vless_uuid,
        }

        v._load = lambda: copy.deepcopy(self.cfg)
        v._get_client = self._get_client
        v._persist = self._persist
        v._validate_config = lambda cfg: None
        v._dx_runtime_add = self._runtime_add
        v._dx_runtime_remove = self._runtime_remove
        v._v30_registry_item = lambda name: {
            "managed_profile": True,
            "profile_lock_hash": "lock-hash",
            "expires_at": 1800000000,
            "access_state": "active",
            "bound_device_id": "a1b2c3d4e5f60708",
        }
        v._ALIGN_PROFILE_DIR = root / "profiles"
        v._align_mkdirs = lambda: v._ALIGN_PROFILE_DIR.mkdir(
            mode=0o700, parents=True, exist_ok=True
        )

    def tearDown(self):
        for key, value in self.saved.items():
            if key == "load":
                v._load = value
            elif key == "get_client":
                v._get_client = value
            elif key == "persist":
                v._persist = value
            elif key == "validate":
                v._validate_config = value
            elif key == "runtime_add":
                v._dx_runtime_add = value
            elif key == "runtime_remove":
                v._dx_runtime_remove = value
            elif key == "registry":
                v._v30_registry_item = value
            elif key == "mkdirs":
                v._align_mkdirs = value
            elif key == "profile_dir":
                v._ALIGN_PROFILE_DIR = value
            elif key == "base_replace":
                v._dx_base_replace_vless_uuid = value
        self.tmp.cleanup()

    def _get_client(self, name):
        cfg = copy.deepcopy(self.cfg)
        return cfg, copy.deepcopy(v._dx_main_client(cfg, name))

    def _persist(self, cfg):
        self.cfg = copy.deepcopy(cfg)

    def _runtime_add(self, client, source_cfg, tag):
        self.runtime.append(("add", tag, client["email"], client["id"]))

    def _runtime_remove(self, email, tag):
        self.runtime.append(("remove", tag, email))

    def _clients(self, tag):
        return next(
            ib["settings"]["clients"]
            for ib in self.cfg["inbounds"]
            if ib["tag"] == tag
        )

    def test_user_route_assignment_is_enforced_in_xray(self):
        result = v.set_direct_routes("alice", ["parspack-direct"])
        self.assertTrue(result["enforced"])
        self.assertEqual(result["active_route_ids"], ["parspack-direct"])
        self.assertEqual(dr.assigned_route_ids("alice"), ["parspack-direct"])
        self.assertEqual(len(self._clients("vless-parspack-direct")), 1)
        self.assertEqual(len(self._clients("vless-arvan-direct")), 0)
        self.assertIn(("add", "vless-parspack-direct", "alice", UUID_OLD), self.runtime)

        v.set_direct_routes("alice", ["arvan-direct"])
        self.assertEqual(len(self._clients("vless-parspack-direct")), 0)
        self.assertEqual(len(self._clients("vless-arvan-direct")), 1)

    def test_global_disable_removes_access_and_enable_restores_assignment(self):
        v.set_direct_routes("alice", ["parspack-direct"])
        v.set_direct_route_enabled("parspack-direct", False)
        self.assertEqual(len(self._clients("vless-parspack-direct")), 0)
        self.assertEqual(dr.assigned_route_ids("alice"), ["parspack-direct"])
        self.assertEqual(dr.user_route_ids("alice"), [])

        v.set_direct_route_enabled("parspack-direct", True)
        self.assertEqual(len(self._clients("vless-parspack-direct")), 1)
        self.assertEqual(
            self._clients("vless-parspack-direct")[0]["id"],
            UUID_OLD,
        )

    def test_direct_bundle_requires_device_binding_and_live_membership(self):
        v.set_direct_routes("alice", ["parspack-direct", "arvan-direct"])
        result = v.direct_config_payload("alice")
        self.assertEqual(result["profile_count"], 2)
        self.assertTrue(result["device_bound"])

        lines = [x for x in result["bundle"].splitlines() if x]
        decoded = [
            base64.b64decode(uri[len("slipnet://"):]).decode().split("|")
            for uri in lines
        ]
        self.assertTrue(all(len(fields) == 84 for fields in decoded))
        self.assertTrue(all(fields[62] == UUID_OLD for fields in decoded))
        self.assertTrue(all(fields[31] == "1" for fields in decoded))
        self.assertTrue(all(fields[35] == "a1b2c3d4e5f60708" for fields in decoded))
        self.assertTrue(all(fields[79] == "" for fields in decoded))
        self.assertTrue(all(fields[80] == "" for fields in decoded))
        self.assertTrue(all(fields[81] == "" for fields in decoded))

        v._v30_registry_item = lambda name: {
            "managed_profile": True,
            "profile_lock_hash": "lock-hash",
            "access_state": "active",
            "bound_device_id": "",
        }
        with self.assertRaises(RuntimeError):
            v.direct_config_payload("alice")

    def test_uuid_rotation_syncs_all_active_direct_inbounds(self):
        v.set_direct_routes("alice", ["parspack-direct", "arvan-direct"])

        calls = []
        def fake_base(name, replacement_uuid, snapshot_usage=True):
            main = next(
                ib for ib in self.cfg["inbounds"]
                if ib["tag"] == v.TAG
            )
            old = main["settings"]["clients"][0]["id"]
            main["settings"]["clients"][0]["id"] = replacement_uuid
            calls.append((old, replacement_uuid, snapshot_usage))
            return old, replacement_uuid

        v._dx_base_replace_vless_uuid = fake_base
        old_uuid, new_uuid = v._v31_replace_vless_uuid(
            "alice", UUID_NEW, snapshot_usage=False
        )
        self.assertEqual(old_uuid, UUID_OLD)
        self.assertEqual(new_uuid, UUID_NEW)
        self.assertEqual(
            self._clients("vless-parspack-direct")[0]["id"],
            UUID_NEW,
        )
        self.assertEqual(
            self._clients("vless-arvan-direct")[0]["id"],
            UUID_NEW,
        )
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
