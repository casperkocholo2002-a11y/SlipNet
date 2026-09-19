#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'SLIPNET_EA_RELEASE_GATE_TEST_FAIL;%s\n' "$1" >&2
  exit 3
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT/tools/android/release_signing_gate.sh"
UNSIGNED="${SLIPNET_TEST_UNSIGNED_APK:-}"
if [[ -z "$UNSIGNED" ]]; then
  mapfile -t candidates < <(find "$ROOT/app/build/outputs/apk/personal/release" -maxdepth 1 -type f -name '*universal*.apk' 2>/dev/null | sort)
  [[ ${#candidates[@]} -eq 1 ]] || fail "unsigned_candidate_count=${#candidates[@]}"
  UNSIGNED="${candidates[0]}"
fi
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/home/reos/Android/Sdk}}"
APKSIGNER="$SDK_ROOT/build-tools/37.0.0/apksigner"
TMP="$(mktemp -d /tmp/slipnet-ea-release-gate-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

[[ -x "$GATE" ]] || fail 'gate_not_executable'
[[ -f "$UNSIGNED" ]] || fail 'unsigned_release_missing'
[[ -x "$APKSIGNER" ]] || fail 'apksigner_missing'

set +e
NO_SECRET="$(env -i PATH="$PATH" ANDROID_HOME="$SDK_ROOT" SLIPNET_RELEASE_UNSIGNED_APK="$UNSIGNED" "$GATE" 2>&1)"
NO_SECRET_RC=$?
set -e
[[ $NO_SECRET_RC -eq 2 ]] || fail "no_secret_rc=$NO_SECRET_RC"
printf '%s\n' "$NO_SECRET" | grep -q 'missing_env=SLIPNET_RELEASE_KEYSTORE' || fail 'no_secret_reason'
KEYSTORE="$TMP/test.jks"
CERT_DER="$TMP/cert.der"
OUTPUT="$TMP/signed.apk"
TEST_PASSWORD='testpass'

keytool -genkeypair \
  -keystore "$KEYSTORE" \
  -storepass "$TEST_PASSWORD" \
  -keypass "$TEST_PASSWORD" \
  -alias slipnet-ea-test \
  -keyalg RSA \
  -keysize 2048 \
  -validity 2 \
  -dname 'CN=SlipNet EA Release Gate Ephemeral,O=SlipNet,C=US' \
  -noprompt >/dev/null 2>&1
keytool -exportcert \
  -keystore "$KEYSTORE" \
  -storepass "$TEST_PASSWORD" \
  -alias slipnet-ea-test \
  -file "$CERT_DER" >/dev/null 2>&1
EXPECTED_CERT="$(sha256sum "$CERT_DER" | awk '{print $1}')"

export ANDROID_HOME="$SDK_ROOT"
export SLIPNET_RELEASE_UNSIGNED_APK="$UNSIGNED"
export SLIPNET_RELEASE_KEYSTORE="$KEYSTORE"
export SLIPNET_RELEASE_KEY_ALIAS=slipnet-ea-test
export SLIPNET_RELEASE_STORE_PASSWORD="$TEST_PASSWORD"
export SLIPNET_RELEASE_KEY_PASSWORD="$TEST_PASSWORD"
export SLIPNET_RELEASE_CERT_SHA256="$EXPECTED_CERT"
export SLIPNET_BASELINE_VERSION_CODE=0
export SLIPNET_ROLLBACK_DATA_POLICY=0
export SLIPNET_RELEASE_OUTPUT_APK="$OUTPUT"

PASS_OUTPUT="$($GATE)" || fail 'positive_path_failed'
printf '%s\n' "$PASS_OUTPUT" | grep -q '^SLIPNET_EA_RELEASE_ARTIFACT;' || fail 'positive_artifact_marker'
printf '%s\n' "$PASS_OUTPUT" | grep -q '^SLIPNET_EA_ROLLBACK_INSTALL_CONTRACT=' || fail 'positive_contract_marker'
[[ -f "$OUTPUT" ]] || fail 'positive_output_missing'
"$APKSIGNER" verify --verbose --print-certs "$OUTPUT" >/dev/null 2>&1 || fail 'positive_verify'
rm -f "$OUTPUT"

export SLIPNET_RELEASE_CERT_SHA256="$(printf '0%.0s' {1..64})"
set +e
MISMATCH_OUTPUT="$($GATE 2>&1)"
MISMATCH_RC=$?
set -e
[[ $MISMATCH_RC -eq 2 ]] || fail "signer_mismatch_rc=$MISMATCH_RC"
printf '%s\n' "$MISMATCH_OUTPUT" | grep -q 'signer_mismatch=' || fail 'signer_mismatch_reason'
[[ ! -e "$OUTPUT" ]] || fail 'signer_mismatch_output_survived'
export SLIPNET_RELEASE_CERT_SHA256="$EXPECTED_CERT"
export SLIPNET_BASELINE_VERSION_CODE=80
set +e
VERSION_OUTPUT="$($GATE 2>&1)"
VERSION_RC=$?
set -e
[[ $VERSION_RC -eq 2 ]] || fail "version_rc=$VERSION_RC"
printf '%s\n' "$VERSION_OUTPUT" | grep -q 'version_not_monotonic=80<=80' || fail 'version_reason'
[[ ! -e "$OUTPUT" ]] || fail 'version_output_survived'

printf 'SLIPNET_EA_RELEASE_GATE_TEST_PASS;noSecret=PASS;positive=PASS;signerMismatch=PASS;versionMonotonic=PASS;cleanup=PASS\n'
