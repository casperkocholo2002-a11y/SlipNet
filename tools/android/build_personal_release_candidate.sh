#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
BUILD_TOOLS_VERSION="${SLIPNET_BUILD_TOOLS_VERSION:-37.0.0}"
BUILD_TOOLS="$SDK_ROOT/build-tools/$BUILD_TOOLS_VERSION"
AAPT2="$BUILD_TOOLS/aapt2"
APKSIGNER="$BUILD_TOOLS/apksigner"
ZIPALIGN="$BUILD_TOOLS/zipalign"

fail() {
  printf 'SLIPNET_EA_UNSIGNED_BUILD_FAIL;%s\n' "$1" >&2
  exit 2
}

[[ -x "$AAPT2" && -x "$APKSIGNER" && -x "$ZIPALIGN" ]] || fail 'missing_build_tools'

cd "$ROOT"
./gradlew -PSLIPNET_EXTERNAL_RELEASE_GATE=true assemblePersonalRelease --no-daemon

mapfile -t candidates < <(find app/build/outputs/apk/personal/release -maxdepth 1 -type f -name '*universal*.apk' | sort)
[[ ${#candidates[@]} -eq 1 ]] || fail "universal_candidate_count=${#candidates[@]}"
APK="${candidates[0]}"

"$ZIPALIGN" -c -P 16 4 "$APK" >/dev/null 2>&1 || fail 'alignment_invalid'
if "$APKSIGNER" verify --verbose --print-certs "$APK" >/dev/null 2>&1; then
  fail 'candidate_unexpectedly_signed'
fi

BADGING_ALL="$("$AAPT2" dump badging "$APK" 2>/dev/null)"
BADGING="$(printf '%s\n' "$BADGING_ALL" | sed -n '1p')"
PACKAGE_NAME="$(printf '%s\n' "$BADGING" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
VERSION_CODE="$(printf '%s\n' "$BADGING" | sed -n "s/^package: name='[^']*' versionCode='\([^']*\)'.*/\1/p")"
[[ "$PACKAGE_NAME" == 'app.slipnet.personal' ]] || fail "package_mismatch=$PACKAGE_NAME"
[[ "$VERSION_CODE" =~ ^[0-9]+$ ]] || fail 'version_code_invalid'

SHA256="$(sha256sum "$APK" | awk '{print $1}')"
printf 'SLIPNET_EA_UNSIGNED_RELEASE_CANDIDATE;package=%s;versionCode=%s;sha256=%s;path=%s\n' \
  "$PACKAGE_NAME" "$VERSION_CODE" "$SHA256" "$APK"
