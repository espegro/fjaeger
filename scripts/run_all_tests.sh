#!/usr/bin/env bash
# Run all Fjaeger host tests
set -euo pipefail

cd "$(dirname "$0")/.."
TEST_BUILD_DIR=$(mktemp -d /tmp/fjaeger-tests.XXXXXX)
trap 'rm -rf -- "$TEST_BUILD_DIR"' EXIT

TESTS=(
    "test_security:tests/test_security.c src/core/state.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_ctap2:tests/test_ctap2.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile:tests/test_profile.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile_erase:tests/test_profile_erase.c src/core/state.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_hmac:tests/test_hmac.c src/core/crypto.c:-lmbedcrypto -Wl,--wrap=mbedtls_sha256,--wrap=mbedtls_sha256_starts,--wrap=mbedtls_sha256_update,--wrap=mbedtls_sha256_finish:-Isrc/core"
    "test_pin_token_scrub:tests/test_pin_token_scrub.c src/fido/cbor.c fuzz/stubs.c:-Wl,--wrap=fj_ecdh_shared_secret,--wrap=fj_aes_cbc,--wrap=fj_state_ctap2_verify:-Isrc/core -Isrc/fido -Isrc/led"
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
