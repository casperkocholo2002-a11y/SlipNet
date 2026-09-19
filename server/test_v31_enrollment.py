import base64
import json
import os
import tempfile
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


def claim(token, device_id, private_key):
    public_key_b64 = _public_key_b64(private_key)
    issued = v.issue_enrollment_challenge(token, device_id, public_key_b64)
    challenge = issued["challenge"]
    message = (
        "slipnet-enroll-challenge-v1\n"
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
        v._vwa.primary_host = self.old_primary_host
        v._vwa.backup_host = self.old_backup_host
        v._vwa.refresh_pair = self.old_refresh_pair
        v._vwa_ws_path = self.old_ws_path
        self.tmp.cleanup()

    def issue(self):
        payload = v._v31_issue_enrollment('alice')
        body = decode_enrollment(payload['uri'])
        self.assertEqual(body['v'], 1)
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
        return body['token']

    def redeem(self, values):
        return v.redeem_enrollment(
            values['token'], values['device_id'], values['public_key_b64'],
            values['challenge'], values['signature_b64'],
        )

    def test_first_device_wins_exact_redeem_retry_is_idempotent_and_file_dies(self):
        token = self.issue()
        key_a = ec.generate_private_key(ec.SECP256R1())
        request_a = claim(token, '0123456789abcdef', key_a)
        first = self.redeem(request_a)
        self.assertTrue(first['device_bound'])
        self.assertIn('0123456789abcdef', first['bundle'])

        # A lost HTTP response may replay the exact same signed redeem request.
        retry = self.redeem(request_a)
        self.assertEqual(first['bundle'], retry['bundle'])

        # Once redeemed, the file cannot mint a fresh challenge even for A.
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            claim(token, '0123456789abcdef', key_a)

        key_b = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(v.EnrollmentAlreadyUsedError):
            claim(token, 'fedcba9876543210', key_b)

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
        self.assertIn("degraded_activity", monitor)
        self.assertIn("users = vless_admin.list_users()", monitor)
        self.assertIn("credentials:'same-origin'", monitor)
        self.assertIn("data[\"vless_users\"] = vless_users", monitor)
        self.assertIn("const users = payload.vless_users || [];", monitor)
        self.assertIn("VLESS user list temporarily unavailable · retrying...", monitor)

    def test_worker_proxy_exposes_only_enrollment_post_routes_plus_websocket(self):
        worker = v._vwa.WORKER_JS
        self.assertIn('request.method === "POST"', worker)
        self.assertIn('"/api/enrollment/challenge"', worker)
        self.assertIn('"/api/enrollment/redeem"', worker)
        self.assertIn('upgrade.toLowerCase() !== "websocket"', worker)
        self.assertIn('return new Response("Not Found"', worker)

    def test_legacy_managed_user_requires_reset_device_before_delivery(self):
        with self.assertRaisesRegex(RuntimeError, "Reset Device"):
            v.config_payload("alice")

    def test_unregistered_legacy_user_also_requires_reset_device(self):
        v._align_atomic_json(v._ALIGN_REGISTRY_FILE, {"version": 1, "users": {}})
        with self.assertRaisesRegex(RuntimeError, "Reset Device"):
            v.config_payload("alice")

    def test_reissue_rotates_credential_before_issuing_new_token(self):
        calls = []
        old_rotate = v._v31_rotate_vless_uuid
        old_issue = v._v31_issue_enrollment
        try:
            v._v31_rotate_vless_uuid = lambda name: calls.append(("rotate", name)) or "new-uuid"
            v._v31_issue_enrollment = lambda name: calls.append(("issue", name)) or {
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
            result = v.reissue_enrollment("alice")
        finally:
            v._v31_rotate_vless_uuid = old_rotate
            v._v31_issue_enrollment = old_issue

        self.assertEqual(calls, [("rotate", "alice"), ("issue", "alice")])
        self.assertTrue(result["credential_rotated"])

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
