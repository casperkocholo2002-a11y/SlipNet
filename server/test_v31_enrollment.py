import base64
import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault('SLIPNET_VLESS_PUBLIC_HOST', 'example.test')
os.environ.setdefault('SLIPNET_WORKER_ORIGIN_HOST', 'origin.example.test')
os.environ.setdefault('SLIPNET_CF_PRIMARY_ACCOUNT_ID', 'primary-test')
os.environ.setdefault('SLIPNET_CF_PRIMARY_SUBDOMAIN', 'primary.workers.dev')
os.environ.setdefault('SLIPNET_CF_BACKUP_ACCOUNT_ID', 'backup-test')
os.environ.setdefault('SLIPNET_CF_BACKUP_SUBDOMAIN', 'backup.workers.dev')

import vless_admin as v
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def decode_enrollment(uri):
    encoded = uri[len(v._V31_ENROLLMENT_SCHEME):]
    encoded += '=' * ((4 - len(encoded) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded).decode())


def _public_key_b64(private_key):
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(public_der).decode()


def claim(
    token,
    device_id,
    private_key,
    claim_version="slipnet-enroll-challenge-v1",
):
    public_key_b64 = _public_key_b64(private_key)
    issued = v.issue_enrollment_challenge(token, device_id, public_key_b64)
    challenge = issued["challenge"]
    message = (
        claim_version + "\n"
        + token + "\n"
        + device_id + "\n"
        + challenge
    ).encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return dict(
        token=token,
        device_id=device_id,
        public_key_b64=public_key_b64,
        challenge=challenge,
        signature_b64=base64.b64encode(signature).decode(),
    )


class EnrollmentV31Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        v._ALIGN_STATE_DIR = root
        v._ALIGN_PROFILE_DIR = root / 'profiles'
        v._ALIGN_REGISTRY_FILE = root / 'registry.json'
        v._ALIGN_USAGE_FILE = root / 'usage.json'
        v._get_client = lambda name: ({}, {'email': 'alice', 'id': '00000000-0000-0000-0000-000000000001'})
        self.real_plain_managed_bundle = v._v30_plain_managed_bundle
        self.real_align_v29_uri = v._align_v29_uri
        v._v30_plain_managed_bundle = lambda name, lock_hash, expiration_ms, bound_device_id='': (
            'slipnet://PRIMARY-' + bound_device_id + '\n' +
            'slipnet://BACKUP-' + bound_device_id + '\n'
        )
        self.old_primary_host = v._vwa.primary_host
        self.old_backup_host = v._vwa.backup_host
        self.old_refresh_pair = v._vwa.refresh_pair
        self.old_ws_path = v._vwa_ws_path
        v._vwa.primary_host = lambda name: 'asset-test.primary.workers.dev'
        v._vwa.backup_host = lambda name: 'cdn-test.backup.workers.dev'
        v._vwa.refresh_pair = lambda name, ws_path: {
            'primary': 'asset-test.primary.workers.dev',
            'backup': 'cdn-test.backup.workers.dev',
        }
        v._vwa_ws_path = lambda: '/ws-test'
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, {
            'version': 1,
            'users': {
                'alice': {
                    'managed_profile': True,
                    'profile_lock_hash': 'lock-hash',
                    'expires_at': 0,
                    'access_state': 'active',
                }
            },
        })

    def tearDown(self):
        v._v30_plain_managed_bundle = self.real_plain_managed_bundle
        v._align_v29_uri = self.real_align_v29_uri
        v._vwa.primary_host = self.old_primary_host
        v._vwa.backup_host = self.old_backup_host
        v._vwa.refresh_pair = self.old_refresh_pair
        v._vwa_ws_path = self.old_ws_path
        self.tmp.cleanup()

    def issue(self):
        payload = v._v31_issue_enrollment('alice')
        body = decode_enrollment(payload['uri'])
        self.assertEqual(body['v'], 2)
        self.assertEqual(payload['version'], 2)
        self.assertEqual(body['name'], 'alice')
        self.assertEqual(
            body['url'],
            'https://asset-test.primary.workers.dev/api/enrollment/redeem',
        )
        self.assertEqual(
            body['backup_url'],
            'https://cdn-test.backup.workers.dev/api/enrollment/redeem',
        )
        self.assertNotIn('00000000-0000-0000-0000-000000000001', payload['uri'])
        reg = v._align_registry()
        self.assertEqual(
            reg['users']['alice']['enrollment_protocol_version'],
            2,
        )
        return body['token']

    def redeem(self, values):
        return v.redeem_enrollment(
            values['token'], values['device_id'], values['public_key_b64'],
            values['challenge'], values['signature_b64'],
        )

    def complete(self, values):
        return v.complete_enrollment(
            values['token'], values['device_id'], values['public_key_b64'],
            values['challenge'], values['signature_b64'],
        )

    def test_real_managed_bundle_contains_primary_backup_and_device_binding(self):
        def fake_v29_uri(actual, host, label, spec):
            fields = [""] * 84
            fields[0] = "29"
            fields[1] = label
            fields[2] = host
            return "slipnet://" + base64.b64encode("|".join(fields).encode()).decode()

        mocked_bundle = v._v30_plain_managed_bundle
        mocked_align = v._align_v29_uri
        try:
            v._v30_plain_managed_bundle = self.real_plain_managed_bundle
            v._align_v29_uri = fake_v29_uri
            bundle = v._v30_plain_managed_bundle(
                "alice",
                "lock-hash",
                1234567890000,
                bound_device_id="0123456789abcdef",
            )
        finally:
            v._v30_plain_managed_bundle = mocked_bundle
            v._align_v29_uri = mocked_align

        uris = [line for line in bundle.splitlines() if line]
        self.assertEqual(len(uris), 2)
        decoded = []
        for uri in uris:
            self.assertTrue(uri.startswith("slipnet://"))
            fields = base64.b64decode(uri[len("slipnet://"):]).decode().split("|")
            self.assertEqual(len(fields), 84)
            self.assertEqual(fields[0], "29")
            self.assertEqual(fields[31], "1")
            self.assertEqual(fields[32], "lock-hash")
            self.assertEqual(fields[33], "1234567890000")
            self.assertEqual(fields[34], "0")
            self.assertEqual(fields[35], "0123456789abcdef")
            decoded.append(fields)
        self.assertEqual([fields[1] for fields in decoded], ["Primary", "Backup"])
        self.assertEqual(
            [fields[2] for fields in decoded],
            [
                "asset-test.primary.workers.dev",
                "cdn-test.backup.workers.dev",
            ],
        )

    def test_real_managed_bundle_fails_closed_if_worker_pair_incomplete(self):
        mocked_bundle = v._v30_plain_managed_bundle
        old_backup = v._vwa.backup_host
        try:
            v._v30_plain_managed_bundle = self.real_plain_managed_bundle
            v._vwa.backup_host = lambda name: None
            with self.assertRaisesRegex(RuntimeError, "Primary/backup Worker mapping is incomplete"):
                v._v30_plain_managed_bundle(
                    "alice",
                    "lock-hash",
                    0,
                    bound_device_id="0123456789abcdef",
                )
        finally:
            v._v30_plain_managed_bundle = mocked_bundle
            v._vwa.backup_host = old_backup

    def test_legacy_v1_artifact_keeps_two_phase_redeem_semantics(self):
        token = self.issue()
        reg = v._align_registry()
        reg['users']['alice'].pop('enrollment_protocol_version', None)
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, reg)

        legacy_uri = v._v31_enrollment_uri(
            'alice',
            token,
            protocol_version=1,
        )
        self.assertEqual(decode_enrollment(legacy_uri)['v'], 1)

        key = ec.generate_private_key(ec.SECP256R1())
        device = '0123456789abcdef'

        # v1 never had a completion phase.
        completion = claim(
            token,
            device,
            key,
            claim_version='slipnet-enroll-complete-v1',
        )
        with self.assertRaisesRegex(
            PermissionError,
            'does not require completion',
        ):
            self.complete(completion)

        redeem_request = claim(token, device, key)
        result = self.redeem(redeem_request)
        self.assertEqual(result['enrollment_protocol_version'], 1)
        self.assertEqual(result['enrollment_state'], 'redeemed')
        self.assertIn(device, result['bundle'])

        # Once a v1 redeem succeeds, fresh challenges are forbidden exactly as
        # on the pre-v2 server.
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            claim(token, device, key)

    def test_first_device_wins_redeem_is_recoverable_until_complete_then_file_dies(self):
        token = self.issue()
        key_a = ec.generate_private_key(ec.SECP256R1())
        device_a = '0123456789abcdef'
        request_a = claim(token, device_a, key_a)

        first = self.redeem(request_a)
        self.assertTrue(first['device_bound'])
        self.assertEqual(first['enrollment_protocol_version'], 2)
        self.assertEqual(first['enrollment_state'], 'pending')
        self.assertIn(device_a, first['bundle'])

        # Lost redeem response or process restart before local persistence:
        # same bound device may obtain a fresh challenge and recover the bundle.
        retry_request = claim(token, device_a, key_a)
        retry = self.redeem(retry_request)
        self.assertEqual(first['bundle'], retry['bundle'])

        # A different device remains blocked from the moment A first binds.
        key_b = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            claim(token, 'fedcba9876543210', key_b)

        completion = claim(
            token,
            device_a,
            key_a,
            claim_version='slipnet-enroll-complete-v1',
        )
        completed = self.complete(completion)
        self.assertEqual(completed['enrollment_state'], 'redeemed')

        # After completion the exact file is dead for bundle redemption,
        # including on the original device.
        post_complete_redeem = claim(token, device_a, key_a)
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            self.redeem(post_complete_redeem)

        # Completion itself remains idempotent for crash/lost-response cleanup.
        completion_retry = claim(
            token,
            device_a,
            key_a,
            claim_version='slipnet-enroll-complete-v1',
        )
        self.assertEqual(
            self.complete(completion_retry)['enrollment_state'],
            'redeemed',
        )

    def test_atomic_race_allows_only_one_device(self):
        token = self.issue()
        key_a = ec.generate_private_key(ec.SECP256R1())
        key_b = ec.generate_private_key(ec.SECP256R1())

        def attempt(args):
            device_id, key = args
            try:
                req = claim(token, device_id, key)
                return ('ok', self.redeem(req)['device_id'])
            except v.EnrollmentAlreadyUsedError:
                return ('used', device_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                attempt,
                (
                    ('0123456789abcdef', key_a),
                    ('fedcba9876543210', key_b),
                ),
            ))
        self.assertEqual(sum(1 for state, _ in results if state == 'ok'), 1)
        self.assertEqual(sum(1 for state, _ in results if state == 'used'), 1)

    def test_pending_challenge_blocks_second_device_before_redeem(self):
        token = self.issue()
        key_a = ec.generate_private_key(ec.SECP256R1())
        key_b = ec.generate_private_key(ec.SECP256R1())
        claim(token, '0123456789abcdef', key_a)

        reg = v._align_registry()
        self.assertEqual(reg['users']['alice']['enrollment_state'], 'pending')
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            v.issue_enrollment_challenge(
                token,
                'fedcba9876543210',
                _public_key_b64(key_b),
            )

    def test_complete_before_bundle_issue_fails_closed(self):
        token = self.issue()
        key = ec.generate_private_key(ec.SECP256R1())
        completion = claim(
            token,
            '0123456789abcdef',
            key,
            claim_version='slipnet-enroll-complete-v1',
        )
        with self.assertRaisesRegex(
            PermissionError,
            "bundle must be issued",
        ):
            self.complete(completion)

    def test_expired_server_challenge_fails_closed(self):
        token = self.issue()
        key = ec.generate_private_key(ec.SECP256R1())
        req = claim(token, '0123456789abcdef', key)
        reg = v._align_registry()
        reg['users']['alice']['enrollment_challenge_expires_at'] = int(time.time()) - 1
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, reg)
        with self.assertRaises(PermissionError):
            self.redeem(req)

    def test_monitor_effective_ui_and_routes_expose_enrollment_lifecycle(self):
        monitor = Path(__file__).with_name('slipnet_monitor.py').read_text()
        effective_ui = monitor.split('/* VLESS_ACTIVITY_UI_V2 */', 1)[1]
        self.assertIn("Enrollment:", effective_ui)
        self.assertIn("Device bound", effective_ui)
        self.assertIn("Reset Device", effective_ui)
        self.assertIn("/api/enrollment/challenge", monitor)
        self.assertIn("/api/enrollment/redeem", monitor)
        self.assertIn("/api/enrollment/complete", monitor)
        self.assertIn("degraded_activity", monitor)
        self.assertIn("users = vless_admin.list_users()", monitor)
        self.assertIn("data[\"vless_users\"] = vless_users", monitor)
        self.assertIn("renderVlessUsersFromData(", monitor)
        self.assertIn("data.vless_users || []", monitor)
        self.assertIn("Boolean(data.vless_users_degraded)", monitor)
        self.assertIn("data.vless_users_error || ''", monitor)
        self.assertIn("function renderVlessUsersFromData(users, degraded=false, error='')", monitor)
        self.assertEqual(monitor.count("async function loadVlessUsers()"), 1)
        self.assertNotIn("__vlessLegacyTimer", monitor)
        self.assertNotIn("__vlessActivityTimer", monitor)
        self.assertIn("enrollmentState === 'unused'", effective_ui)
        self.assertIn("Reset Device to issue one-time file", effective_ui)
        self.assertIn("Activation pending on first device", effective_ui)
        self.assertIn("One-time file already used", effective_ui)
        self.assertIn("Activate the subscription before resetting the device", effective_ui)
        self.assertIn("Use Reset Device if you need a new one-time file", monitor)
        self.assertNotIn("Rotate password to issue an artifact", monitor)

    def test_worker_proxy_exposes_only_enrollment_post_routes_plus_websocket(self):
        worker = v._vwa.WORKER_JS
        self.assertIn('request.method === "POST"', worker)
        self.assertIn('"/api/enrollment/challenge"', worker)
        self.assertIn('"/api/enrollment/redeem"', worker)
        self.assertIn('"/api/enrollment/complete"', worker)
        self.assertIn('upgrade.toLowerCase() !== "websocket"', worker)
        self.assertIn('return new Response("Not Found"', worker)

    def test_legacy_password_artifact_path_is_disabled(self):
        with self.assertRaisesRegex(RuntimeError, "one-time enrollment"):
            v.rotate_delivery_password("alice", "abcdef")

    def test_config_payload_state_matrix(self):
        token = self.issue()
        unused = v.config_payload("alice")
        self.assertTrue(unused["one_time_enrollment"])
        self.assertEqual(unused["profile_count"], 2)

        key = ec.generate_private_key(ec.SECP256R1())
        request = claim(token, "0123456789abcdef", key)
        with self.assertRaisesRegex(RuntimeError, "not available"):
            v.config_payload("alice")

        self.redeem(request)
        with self.assertRaisesRegex(RuntimeError, "not available"):
            v.config_payload("alice")

        completion = claim(
            token,
            "0123456789abcdef",
            key,
            claim_version="slipnet-enroll-complete-v1",
        )
        self.complete(completion)
        with self.assertRaisesRegex(RuntimeError, "already activated"):
            v.config_payload("alice")

    def test_config_payload_refuses_blocked_subscription(self):
        self.issue()
        reg = v._align_registry()
        reg["users"]["alice"]["access_state"] = "quota_exceeded"
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, reg)
        with self.assertRaisesRegex(RuntimeError, "Subscription is not active"):
            v.config_payload("alice")

    def test_expired_unused_artifact_is_reissued_with_fresh_token(self):
        first_payload = v._v31_issue_enrollment("alice")
        first = decode_enrollment(first_payload["uri"])
        reg = v._align_registry()
        reg["users"]["alice"]["enrollment_expires_at"] = int(time.time()) - 1
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, reg)

        refreshed_payload = v.config_payload("alice")
        refreshed = decode_enrollment(refreshed_payload["uri"])
        self.assertNotEqual(first["token"], refreshed["token"])
        self.assertEqual(refreshed["name"], "alice")
        reg = v._align_registry()
        self.assertEqual(reg["users"]["alice"]["enrollment_state"], "unused")
        self.assertGreater(reg["users"]["alice"]["enrollment_expires_at"], int(time.time()))

    def test_legacy_managed_user_requires_reset_device_before_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "Reset Device"):
            v.config_payload("alice")

    def test_unregistered_legacy_user_also_requires_reset_device(self):
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, {"version": 1, "users": {}})
        with self.assertRaisesRegex(RuntimeError, "Reset Device"):
            v.config_payload("alice")

    def test_worker_refresh_requires_complete_pair_before_upload(self):
        old_read_map = v._vwa._read_map
        old_upload = v._vwa._upload_worker
        old_ws_test = v._vwa._ws_test
        calls = []
        try:
            def read_map(path):
                if path == v._vwa.PRIMARY["map_file"]:
                    return {
                        "alice": {
                            "worker": "primary-worker",
                            "hostname": "primary.example.test",
                        }
                    }
                return {}

            v._vwa._read_map = read_map
            v._vwa._upload_worker = (
                lambda spec, worker: calls.append(("upload", worker))
            )
            v._vwa._ws_test = (
                lambda host, ws_path: calls.append(("ws", host))
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "Primary/backup Worker mapping is incomplete",
            ):
                self.old_refresh_pair("alice", "/ws-test")
        finally:
            v._vwa._read_map = old_read_map
            v._vwa._upload_worker = old_upload
            v._vwa._ws_test = old_ws_test

        self.assertEqual(calls, [])

    def test_uuid_replace_persist_failure_restores_old_runtime(self):
        calls = []
        old_base_list = v._v31_base_list_users
        old_load = v._load
        old_clients = v._clients
        old_validate = v._validate_config
        old_remove = v._runtime_remove
        old_add = v._runtime_add
        old_persist = v._persist
        try:
            cfg = {
                "inbounds": [{
                    "settings": {
                        "clients": [{
                            "email": "alice",
                            "id": "00000000-0000-0000-0000-000000000001",
                        }]
                    }
                }]
            }
            v._v31_base_list_users = (
                lambda: calls.append(("snapshot-usage",))
            )
            v._load = lambda: json.loads(json.dumps(cfg))
            v._clients = (
                lambda value:
                value["inbounds"][0]["settings"]["clients"]
            )
            v._validate_config = (
                lambda value: calls.append(
                    ("validate", v._clients(value)[0]["id"])
                )
            )
            v._runtime_remove = (
                lambda email: calls.append(("remove", email))
            )
            v._runtime_add = (
                lambda client, source:
                calls.append(("add", client["id"]))
            )

            def fail_persist(value):
                calls.append(("persist", v._clients(value)[0]["id"]))
                raise RuntimeError("synthetic persist failure")

            v._persist = fail_persist

            with self.assertRaisesRegex(
                RuntimeError,
                "synthetic persist failure",
            ):
                v._v31_replace_vless_uuid(
                    "alice",
                    "00000000-0000-0000-0000-000000000002",
                    snapshot_usage=True,
                )
        finally:
            v._v31_base_list_users = old_base_list
            v._load = old_load
            v._clients = old_clients
            v._validate_config = old_validate
            v._runtime_remove = old_remove
            v._runtime_add = old_add
            v._persist = old_persist

        self.assertEqual(
            calls,
            [
                ("snapshot-usage",),
                ("validate", "00000000-0000-0000-0000-000000000002"),
                ("remove", "alice"),
                ("add", "00000000-0000-0000-0000-000000000002"),
                ("persist", "00000000-0000-0000-0000-000000000002"),
                ("remove", "alice"),
                ("add", "00000000-0000-0000-0000-000000000001"),
            ],
        )

    def test_uuid_replace_reports_runtime_rollback_failure(self):
        old_base_list = v._v31_base_list_users
        old_load = v._load
        old_clients = v._clients
        old_validate = v._validate_config
        old_remove = v._runtime_remove
        old_add = v._runtime_add
        old_persist = v._persist
        try:
            cfg = {
                "inbounds": [{
                    "settings": {
                        "clients": [{
                            "email": "alice",
                            "id": "00000000-0000-0000-0000-000000000001",
                        }]
                    }
                }]
            }
            v._v31_base_list_users = lambda: None
            v._load = lambda: json.loads(json.dumps(cfg))
            v._clients = (
                lambda value:
                value["inbounds"][0]["settings"]["clients"]
            )
            v._validate_config = lambda value: None
            v._runtime_remove = lambda email: None

            add_count = {"value": 0}

            def add(client, source):
                add_count["value"] += 1
                if add_count["value"] == 2:
                    raise RuntimeError("restore-old failed")

            v._runtime_add = add
            v._persist = (
                lambda value:
                (_ for _ in ()).throw(RuntimeError("persist failed"))
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "runtime rollback was incomplete",
            ):
                v._v31_replace_vless_uuid(
                    "alice",
                    "00000000-0000-0000-0000-000000000002",
                    snapshot_usage=False,
                )
        finally:
            v._v31_base_list_users = old_base_list
            v._load = old_load
            v._clients = old_clients
            v._validate_config = old_validate
            v._runtime_remove = old_remove
            v._runtime_add = old_add
            v._persist = old_persist

    def test_reissue_preflights_workers_before_rotate_and_issues_without_second_refresh(self):
        calls = []
        old_refresh = v._vwa.refresh_pair
        old_rotate = v._v31_rotate_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            v._vwa.refresh_pair = lambda name, ws_path: (
                calls.append(("refresh", name, ws_path))
                or {
                    "primary": "asset-test.primary.workers.dev",
                    "backup": "cdn-test.backup.workers.dev",
                }
            )
            v._v31_rotate_vless_uuid = lambda name: (
                calls.append(("rotate", name))
                or (
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                )
            )
            v._v31_issue_enrollment = lambda name, refresh_workers=True: (
                calls.append(("issue", name, refresh_workers))
                or {
                    "success": True,
                    "name": name,
                    "uri": "slipnet-enroll://test",
                    "bundle": "slipnet-enroll://test",
                    "filename": "alice.slipnet",
                    "profile_count": 2,
                    "version": 1,
                    "one_time_enrollment": True,
                    "enrollment_state": "unused",
                    "enrollment_expires_at": 123,
                }
            )
            result = v.reissue_enrollment("alice")
        finally:
            v._vwa.refresh_pair = old_refresh
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_issue_enrollment = old_issue

        self.assertEqual(
            calls,
            [
                ("refresh", "alice", "/ws-test"),
                ("rotate", "alice"),
                ("issue", "alice", False),
            ],
        )
        self.assertTrue(result["credential_rotated"])

    def test_reissue_worker_failure_leaves_credential_and_enrollment_untouched(self):
        before_meta = v._v30_registry_item("alice")
        before_path = v._v30_artifact_path("alice")
        before_bytes = before_path.read_bytes() if before_path.exists() else None
        calls = []

        old_refresh = v._vwa.refresh_pair
        old_rotate = v._v31_rotate_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            def fail_refresh(name, ws_path):
                calls.append(("refresh", name))
                raise RuntimeError("synthetic worker failure")

            v._vwa.refresh_pair = fail_refresh
            v._v31_rotate_vless_uuid = (
                lambda name: calls.append(("rotate", name))
            )
            v._v31_issue_enrollment = (
                lambda name, refresh_workers=True:
                calls.append(("issue", name, refresh_workers))
            )

            with self.assertRaisesRegex(RuntimeError, "synthetic worker failure"):
                v.reissue_enrollment("alice")
        finally:
            v._vwa.refresh_pair = old_refresh
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_issue_enrollment = old_issue

        self.assertEqual(calls, [("refresh", "alice")])
        self.assertEqual(v._v30_registry_item("alice"), before_meta)
        after_bytes = before_path.read_bytes() if before_path.exists() else None
        self.assertEqual(after_bytes, before_bytes)

    def test_reissue_issue_failure_rolls_back_uuid_registry_and_artifact(self):
        self.issue()
        before_meta = v._v30_registry_item("alice")
        path = v._v30_artifact_path("alice")
        before_bytes = path.read_bytes()
        before_mode = path.stat().st_mode & 0o777
        calls = []

        old_refresh = v._vwa.refresh_pair
        old_rotate = v._v31_rotate_vless_uuid
        old_replace = v._v31_replace_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            v._vwa.refresh_pair = lambda name, ws_path: {
                "primary": "asset-test.primary.workers.dev",
                "backup": "cdn-test.backup.workers.dev",
            }
            v._v31_rotate_vless_uuid = lambda name: (
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            )
            v._v31_replace_vless_uuid = (
                lambda name, replacement_uuid, snapshot_usage=True:
                calls.append(
                    ("rollback", name, replacement_uuid, snapshot_usage)
                )
                or (
                    "00000000-0000-0000-0000-000000000002",
                    replacement_uuid,
                )
            )

            def fail_issue(name, refresh_workers=True):
                v._v30_registry_update(name, {
                    "enrollment_state": "redeemed",
                    "enrollment_token_hash": "corrupt",
                })
                v._v30_artifact_path(name).write_bytes(b"corrupt-artifact")
                raise RuntimeError("synthetic issue failure")

            v._v31_issue_enrollment = fail_issue

            with self.assertRaisesRegex(RuntimeError, "synthetic issue failure"):
                v.reissue_enrollment("alice")
        finally:
            v._vwa.refresh_pair = old_refresh
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_replace_vless_uuid = old_replace
            v._v31_issue_enrollment = old_issue

        self.assertEqual(
            calls,
            [(
                "rollback",
                "alice",
                "00000000-0000-0000-0000-000000000001",
                False,
            )],
        )
        self.assertEqual(v._v30_registry_item("alice"), before_meta)
        self.assertEqual(path.read_bytes(), before_bytes)
        self.assertEqual(path.stat().st_mode & 0o777, before_mode)

    def test_reissue_surfaces_incomplete_rollback(self):
        old_refresh = v._vwa.refresh_pair
        old_rotate = v._v31_rotate_vless_uuid
        old_replace = v._v31_replace_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            v._vwa.refresh_pair = lambda name, ws_path: {
                "primary": "asset-test.primary.workers.dev",
                "backup": "cdn-test.backup.workers.dev",
            }
            v._v31_rotate_vless_uuid = lambda name: (
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            )
            v._v31_replace_vless_uuid = (
                lambda *args, **kwargs:
                (_ for _ in ()).throw(RuntimeError("rollback failed"))
            )
            v._v31_issue_enrollment = (
                lambda *args, **kwargs:
                (_ for _ in ()).throw(RuntimeError("issue failed"))
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "rollback was incomplete",
            ):
                v.reissue_enrollment("alice")
        finally:
            v._vwa.refresh_pair = old_refresh
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_replace_vless_uuid = old_replace
            v._v31_issue_enrollment = old_issue

    def test_reissue_lock_serializes_concurrent_reset_device_calls(self):
        active = 0
        max_active = 0
        guard = threading.Lock()

        old_refresh = v._vwa.refresh_pair
        old_rotate = v._v31_rotate_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            def refresh(name, ws_path):
                nonlocal active, max_active
                with guard:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.03)
                with guard:
                    active -= 1
                return {
                    "primary": "asset-test.primary.workers.dev",
                    "backup": "cdn-test.backup.workers.dev",
                }

            v._vwa.refresh_pair = refresh
            v._v31_rotate_vless_uuid = lambda name: (
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
            )
            v._v31_issue_enrollment = lambda name, refresh_workers=True: {
                "success": True,
                "name": name,
                "uri": "slipnet-enroll://test",
                "bundle": "slipnet-enroll://test",
                "filename": "alice.slipnet",
                "profile_count": 2,
                "version": 1,
                "one_time_enrollment": True,
                "enrollment_state": "unused",
                "enrollment_expires_at": 123,
            }

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(
                    lambda _: v.reissue_enrollment("alice"),
                    range(2),
                ))
        finally:
            v._vwa.refresh_pair = old_refresh
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_issue_enrollment = old_issue

        self.assertEqual(max_active, 1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(x["credential_rotated"] for x in results))

    def test_expired_file_and_invalid_signature_fail_closed(self):
        token = self.issue()
        key = ec.generate_private_key(ec.SECP256R1())
        req = claim(token, '0123456789abcdef', key)
        bad = dict(req)
        bad['signature_b64'] = base64.b64encode(b'not-a-signature').decode()
        with self.assertRaises((PermissionError, ValueError)):
            self.redeem(bad)

        reg = v._align_registry()
        reg['users']['alice']['enrollment_expires_at'] = int(time.time()) - 1
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, reg)
        with self.assertRaises(PermissionError):
            self.redeem(req)


if __name__ == '__main__':
    unittest.main(verbosity=2)
