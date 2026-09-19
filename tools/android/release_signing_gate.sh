#!/usr/bin/env bash
set -euo pipefail

fail() {
  if [[ -n "${OUTPUT_APK:-}" && -f "${OUTPUT_APK:-}" ]]; then
    rm -f "$OUTPUT_APK"
  fi
  printf 'SLIPNET_EA_RELEASE_GATE_FAIL;%s\n' "$1" >&2
  exit 2
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "missing_env=$name"
}

require_env SLIPNET_RELEASE_KEYSTORE
require_env SLIPNET_RELEASE_KEY_ALIAS
require_env SLIPNET_RELEASE_STORE_PASSWORD
require_env SLIPNET_RELEASE_KEY_PASSWORD
require_env SLIPNET_RELEASE_CERT_SHA256
require_env SLIPNET_BASELINE_VERSION_CODE
require_env SLIPNET_ROLLBACK_DATA_POLICY

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
[[ -n "$SDK_ROOT" ]] || fail 'missing_android_sdk_root'
BUILD_TOOLS_VERSION="${SLIPNET_BUILD_TOOLS_VERSION:-37.0.0}"
BUILD_TOOLS="$SDK_ROOT/build-tools/$BUILD_TOOLS_VERSION"
APKSIGNER="$BUILD_TOOLS/apksigner"
AAPT2="$BUILD_TOOLS/aapt2"
ZIPALIGN="$BUILD_TOOLS/zipalign"
[[ -x "$APKSIGNER" && -x "$AAPT2" && -x "$ZIPALIGN" ]] || fail 'missing_build_tools'
UNSIGNED_APK="${SLIPNET_RELEASE_UNSIGNED_APK:-}"
OUTPUT_APK="${SLIPNET_RELEASE_OUTPUT_APK:-.local/release/SlipNet-EA-personal-release.apk}"
[[ -n "$UNSIGNED_APK" ]] || fail 'missing_env=SLIPNET_RELEASE_UNSIGNED_APK'
KEYSTORE="$SLIPNET_RELEASE_KEYSTORE"
EXPECTED_CERT="$(printf '%s' "$SLIPNET_RELEASE_CERT_SHA256" | tr '[:upper:]' '[:lower:]' | tr -d ':')"
BASELINE_VERSION="$SLIPNET_BASELINE_VERSION_CODE"
ROLLBACK_POLICY="$SLIPNET_ROLLBACK_DATA_POLICY"

[[ -f "$UNSIGNED_APK" ]] || fail 'unsigned_apk_missing'
[[ -f "$KEYSTORE" ]] || fail 'keystore_missing'
"$ZIPALIGN" -c -P 16 4 "$UNSIGNED_APK" >/dev/null 2>&1 || fail 'unsigned_apk_alignment_invalid'
[[ "$EXPECTED_CERT" =~ ^[0-9a-f]{64}$ ]] || fail 'expected_cert_sha256_invalid'
[[ "$BASELINE_VERSION" =~ ^[0-9]+$ ]] || fail 'baseline_version_code_invalid'
[[ "$ROLLBACK_POLICY" =~ ^[012]$ ]] || fail 'rollback_data_policy_invalid'

BADGING_ALL="$($AAPT2 dump badging "$UNSIGNED_APK" 2>/dev/null)"
BADGING="$(printf '%s\n' "$BADGING_ALL" | sed -n '1p')"
PACKAGE_NAME="$(printf '%s\n' "$BADGING" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
CANDIDATE_VERSION="$(printf '%s\n' "$BADGING" | sed -n "s/^package: name='[^']*' versionCode='\([^']*\)'.*/\1/p")"
[[ "$PACKAGE_NAME" == 'app.slipnet.personal' ]] || fail "package_mismatch=$PACKAGE_NAME"
[[ "$CANDIDATE_VERSION" =~ ^[0-9]+$ ]] || fail 'candidate_version_code_invalid'
(( CANDIDATE_VERSION > BASELINE_VERSION )) || fail "version_not_monotonic=$CANDIDATE_VERSION<=${BASELINE_VERSION}"

mkdir -p "$(dirname "$OUTPUT_APK")"
rm -f "$OUTPUT_APK"
"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$SLIPNET_RELEASE_KEY_ALIAS" \
  --ks-pass env:SLIPNET_RELEASE_STORE_PASSWORD \
  --key-pass env:SLIPNET_RELEASE_KEY_PASSWORD \
  --out "$OUTPUT_APK" \
  "$UNSIGNED_APK"

VERIFY_OUTPUT="$($APKSIGNER verify --verbose --print-certs "$OUTPUT_APK" 2>&1)" || {
  rm -f "$OUTPUT_APK"
  fail 'signed_apk_verification_failed'
}
grep -q '^Verifies$' <<<"$VERIFY_OUTPUT" || fail 'signed_apk_not_verified'
grep -Eq 'Verified using v(2|3) scheme .*true' <<<"$VERIFY_OUTPUT" || fail 'modern_signature_scheme_missing'

ACTUAL_CERT="$(awk -F ': ' '/certificate SHA-256 digest:/ && !found {print $NF; found=1}' <<<"$VERIFY_OUTPUT" | tr '[:upper:]' '[:lower:]' | tr -d ':')"
[[ "$ACTUAL_CERT" =~ ^[0-9a-f]{64}$ ]] || fail 'actual_cert_sha256_missing'
if [[ "$ACTUAL_CERT" != "$EXPECTED_CERT" ]]; then
  rm -f "$OUTPUT_APK"
  fail "signer_mismatch=$ACTUAL_CERT"
fi

APK_SHA256="$(sha256sum "$OUTPUT_APK" | awk '{print $1}')"
printf 'SLIPNET_EA_RELEASE_ARTIFACT;package=%s;versionCode=%s;sha256=%s;certSha256=%s;rollbackDataPolicy=%s;path=%s\n' \
  "$PACKAGE_NAME" \
  "$CANDIDATE_VERSION" \
  "$APK_SHA256" \
  "$ACTUAL_CERT" \
  "$ROLLBACK_POLICY" \
  "$OUTPUT_APK"

printf 'SLIPNET_EA_ROLLBACK_INSTALL_CONTRACT='
printf 'adb install --enable-rollback %q -r %q\n' \
  "$ROLLBACK_POLICY" \
  "$OUTPUT_APK"
