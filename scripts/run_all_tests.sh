#!/usr/bin/env bash
# Run all Fjaeger host tests
set -euo pipefail

cd "$(dirname "$0")/.."
TEST_BUILD_DIR=$(mktemp -d /tmp/fjaeger-tests.XXXXXX)
trap 'rm -rf -- "$TEST_BUILD_DIR"' EXIT

TESTS=(
    "test_factory_confirm:tests/test_factory_confirm.c src/core/factory_confirm.c src/fido/hmac_presence.c::-Isrc/core -Isrc/fido"
    "test_hmac_transport:tests/test_hmac_transport.c src/fido/u2f.c src/fido/hmac_presence.c src/fido/hmac_ctap.c src/fido/hmac_request.c src/fido/hmac_assertion.c src/fido/hmac_enroll.c src/fido/hmac_store.c src/fido/hmac_policy.c src/fido/hmac_secret.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/fido/cbor.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/presence_stubs -Itests/stubs -Isrc/core -Isrc/fido -Isrc/led"
    "test_combined_state_job:tests/test_combined_state_job.c src/core/state.c src/core/keys_stage.c src/core/combined_backup.c src/core/combined_password_job.c src/core/combined_device_backup.c src/core/combined_device_restore.c src/core/restore_boot.c src/core/restore_prepared.c src/core/restore_bundle.c src/core/factory_wipe.c src/core/restore_coordinator.c src/fido/hmac_config.c src/fido/hmac_store.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto -Wl,--wrap=fj_factory_wipe_halt:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_combined_device_backup:tests/test_combined_device_backup.c src/core/combined_device_backup.c src/core/combined_device_restore.c src/core/combined_backup.c src/fido/hmac_backup.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_hmac_presence:tests/test_hmac_presence.c src/fido/hmac_presence.c::-Isrc/fido"
    "test_hmac_config:tests/test_hmac_config.c src/fido/hmac_config.c src/fido/hmac_runtime.c src/fido/hmac_store.c src/fido/hmac_policy.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core -Isrc/fido"
    "test_hmac_assertion:tests/test_hmac_assertion.c src/fido/hmac_ctap.c src/fido/hmac_request.c src/fido/hmac_assertion.c src/fido/hmac_enroll.c src/fido/hmac_store.c src/fido/hmac_policy.c src/fido/hmac_secret.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/fido/cbor.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core -Isrc/fido"
    "test_combined_password_job:tests/test_combined_password_job.c src/core/combined_password_job.c src/core/combined_backup.c src/fido/hmac_backup.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido -Isrc/usb"
    "test_combined_backup:tests/test_combined_backup.c src/core/combined_backup.c src/fido/hmac_backup.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_factory_wipe:tests/test_factory_wipe.c src/core/factory_wipe.c src/core/restore_journal.c::-Itests/stubs -Isrc/core"
    "test_restore_activation:tests/test_restore_activation.c src/core/keys_stage.c src/core/combined_backup.c src/core/combined_password_job.c src/core/combined_device_restore.c src/core/restore_boot.c src/core/restore_prepared.c src/core/restore_bundle.c src/core/factory_wipe.c src/core/restore_coordinator.c src/fido/hmac_config.c src/fido/hmac_store.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core -Isrc/fido"
    "test_keys_stage:tests/test_keys_stage.c src/core/keys_stage.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core"
    "test_hmac_stage:tests/test_hmac_stage.c src/fido/hmac_store.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core -Isrc/fido"
    "test_restore_coordinator:tests/test_restore_coordinator.c src/core/restore_coordinator.c src/core/restore_journal.c::-Itests/stubs -Isrc/core"
    "test_restore_journal:tests/test_restore_journal.c src/core/restore_journal.c::-Itests/stubs -Isrc/core"
    "test_hmac_password_backup:tests/test_hmac_password_backup.c src/fido/hmac_backup_password.c src/fido/hmac_backup.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_hmac_backup:tests/test_hmac_backup.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_hmac_root:tests/test_hmac_root.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_hmac_store:tests/test_hmac_store.c src/fido/hmac_store.c src/fido/hmac_backup.c src/fido/hmac_root.c src/fido/hmac_credential.c src/core/restore_journal.c src/core/crypto.c:-lmbedcrypto:-Itests/stubs -Isrc/core -Isrc/fido"
    "test_hmac_credential:tests/test_hmac_credential.c src/fido/hmac_credential.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_hmac_request:tests/test_hmac_request.c src/fido/hmac_request.c src/fido/cbor.c::-Isrc/core -Isrc/fido"
    "test_hmac_policy:tests/test_hmac_policy.c src/fido/hmac_policy.c::-Isrc/fido"
    "test_store_migration:tests/test_store_migration.c::-Itests/stubs -Isrc/core"
    "test_hmac_secret:tests/test_hmac_secret.c src/fido/hmac_secret.c src/core/crypto.c:-lmbedcrypto:-Isrc/core -Isrc/fido"
    "test_presence:tests/test_presence.c src/fido/u2f.c src/fido/hmac_presence.c::-Itests/presence_stubs -Isrc/core -Isrc/fido -Isrc/led"
    "test_security:tests/test_security.c src/core/state.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_ctap2:tests/test_ctap2.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile:tests/test_profile.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile_erase:tests/test_profile_erase.c src/core/state.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_hmac:tests/test_hmac.c src/core/crypto.c:-lmbedcrypto -Wl,--wrap=mbedtls_sha256,--wrap=mbedtls_sha256_starts,--wrap=mbedtls_sha256_update,--wrap=mbedtls_sha256_finish:-Isrc/core"
    "test_pin_token_scrub:tests/test_pin_token_scrub.c src/fido/cbor.c fuzz/stubs.c:-Wl,--wrap=fj_ecdh_shared_secret,--wrap=fj_aes_cbc,--wrap=fj_state_ctap2_verify,--wrap=fj_state_ctap2_pin_configured:-Isrc/core -Isrc/fido -Isrc/led"
    "test_keys_restore:tests/test_keys_restore.c src/core/keys.c::-Itests/stubs -Isrc/core"
    "test_ed25519:tests/test_ed25519.c src/core/ed25519.c third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c::-Isrc/core -Ithird_party/monocypher"
    "test_crypto_gcm:tests/test_crypto_gcm.c src/core/crypto.c:-lmbedcrypto:-Isrc/core"
)

echo "=== Running Fjaeger Host Tests ==="
echo ""

FAILED=()
PASSED=()

for test_spec in "${TESTS[@]}"; do
    IFS=':' read -r name sources libs includes <<< "$test_spec"

    echo -n "Building $name... "

    # Build command
    BUILD_CMD="${CC:-cc} -std=c11 -Wall -Wextra -Werror ${CFLAGS:-}"
    if [ -n "$includes" ]; then
        BUILD_CMD="$BUILD_CMD $includes"
    fi
    BUILD_CMD="$BUILD_CMD $sources $libs -o $TEST_BUILD_DIR/$name"

    if ! $BUILD_CMD > "$TEST_BUILD_DIR/$name.build.log" 2>&1; then
        echo "FAILED (build)"
        cat "$TEST_BUILD_DIR/$name.build.log"
        FAILED+=("$name (build)")
        continue
    fi
    echo "ok"

    echo -n "Running $name... "
    if ! "$TEST_BUILD_DIR/$name" > "$TEST_BUILD_DIR/$name.log" 2>&1; then
        echo "FAILED"
        cat "$TEST_BUILD_DIR/$name.log"
        FAILED+=("$name")
    else
        # Extract the final "ok" line
        RESULT=$(tail -1 "$TEST_BUILD_DIR/$name.log")
        echo "$RESULT"
        PASSED+=("$name")
    fi
    echo ""
done

echo "==================================================================="
echo "Test Results:"
echo "==================================================================="
echo "PASSED: ${#PASSED[@]}"
for t in "${PASSED[@]}"; do
    echo "  ✓ $t"
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "FAILED: ${#FAILED[@]}"
    for t in "${FAILED[@]}"; do
        echo "  ✗ $t"
    done
    exit 1
fi

echo ""
echo "All tests passed ✓"
