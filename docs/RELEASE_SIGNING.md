# SlipNet EA release signing

SlipNet EA Personal releases use a two-stage, fail-closed pipeline.

1. `tools/android/build_personal_release_candidate.sh` builds an **unsigned** `app.slipnet.personal` universal APK using the explicit `SLIPNET_EXTERNAL_RELEASE_GATE` Gradle mode. The script verifies package identity, 16 KiB alignment, version code, and that the candidate is not already signed.
2. `tools/android/release_signing_gate.sh` accepts signing material only from external environment variables, signs the candidate, verifies a modern APK signature, pins the exact signer certificate SHA-256, enforces monotonic `versionCode`, and emits the qualified artifact plus a non-executed rollback-install contract.

Normal `assemblePersonalRelease` behavior remains fail-closed: without a configured release keystore it must not silently produce a publishable release. The unsigned path exists only behind the explicit external-gate Gradle property.

## Required production inputs

Keep all of these outside the repository:

- `SLIPNET_RELEASE_KEYSTORE`: path to the persistent production keystore.
- `SLIPNET_RELEASE_KEY_ALIAS`: production key alias.
- `SLIPNET_RELEASE_STORE_PASSWORD`: keystore password.
- `SLIPNET_RELEASE_KEY_PASSWORD`: key password.
- `SLIPNET_RELEASE_CERT_SHA256`: independently recorded SHA-256 of the production signing certificate.
- `SLIPNET_BASELINE_VERSION_CODE`: highest version code already released to users; candidate must be strictly greater.
- `SLIPNET_ROLLBACK_DATA_POLICY`: Android rollback data policy (`0`, `1`, or `2`).
- `SLIPNET_RELEASE_UNSIGNED_APK`: path emitted by the unsigned-candidate builder.

Optional:

- `SLIPNET_RELEASE_OUTPUT_APK`: destination for the qualified APK. Default: `.local/release/SlipNet-EA-personal-release.apk`.
- `SLIPNET_BUILD_TOOLS_VERSION`: Android build-tools version. Default: `37.0.0`.

## Qualification commands

```bash
tools/android/build_personal_release_candidate.sh

export SLIPNET_RELEASE_UNSIGNED_APK='app/build/outputs/apk/personal/release/SlipNet-vX-personal-release-universal.apk'
export SLIPNET_RELEASE_KEYSTORE='/secure/external/path/slipnet-ea-production.jks'
export SLIPNET_RELEASE_KEY_ALIAS='...'
export SLIPNET_RELEASE_STORE_PASSWORD='...'
export SLIPNET_RELEASE_KEY_PASSWORD='...'
export SLIPNET_RELEASE_CERT_SHA256='...'
export SLIPNET_BASELINE_VERSION_CODE='...'
export SLIPNET_ROLLBACK_DATA_POLICY='0'

tools/android/release_signing_gate.sh
```

Never commit the keystore, passwords, certificate-private-key material, or a generated `keystore.properties`. `.local/` is ignored and is only a local staging area.

## Test harness

`tools/android/release_signing_gate_test.sh` uses an ephemeral two-day non-production key under `/tmp`. It verifies:

- missing-secret fail-closed behavior;
- successful signing and APK verification;
- exact signer-digest mismatch rejection with output cleanup;
- non-monotonic version rejection;
- cleanup of ephemeral signing material.

The ephemeral test key is never a production signer and must never be used for a user release.


## GitHub Actions

Personal EA deliberately does not recursively initialize legacy DNS/Rust submodules in CI. The Personal flavor builds successfully from a fresh checkout with no submodules initialized; its required Go artifacts are already tracked AARs, and its release path does not depend on the Slipstream Rust cargo task. This avoids stale/unavailable LAB submodules from blocking VLESS-only Personal releases.

`.github/workflows/personal-ea-release.yml` is manual-only and fail-closed. It:

1. builds and validates the unsigned Personal EA candidate;
2. runs the ephemeral signing-gate qualification;
3. refuses production signing unless all five production signer secrets are configured;
4. signs only through `release_signing_gate.sh`;
5. uploads the qualified APK as a short-retention workflow artifact;
6. removes the decoded keystore on every exit path.

Required repository secrets:

- `SLIPNET_EA_KEYSTORE_BASE64`
- `SLIPNET_EA_KEY_ALIAS`
- `SLIPNET_EA_STORE_PASSWORD`
- `SLIPNET_EA_KEY_PASSWORD`
- `SLIPNET_EA_CERT_SHA256`

`CONFIG_ENCRYPTION_KEY` remains a separate build secret.

At the time this gate was introduced, this repository had no configured Actions secrets and no GitHub Release. Therefore no production signer is inferred or generated. For the first real Personal EA release, use the actual independently retained signer and set `baseline_version_code` to the highest versionCode truly distributed under that same signer. If none has ever been distributed under that signer, the baseline is `0`.
