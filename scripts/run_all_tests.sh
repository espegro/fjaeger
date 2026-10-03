#!/usr/bin/env bash
# Run all Fjaeger host tests
set -euo pipefail

cd "$(dirname "$0")/.."

TESTS=(
    "test_security:tests/test_security.c src/core/state.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_ctap2:tests/test_ctap2.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile:tests/test_profile.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Isrc/core -Isrc/fido -Isrc/led"
    "test_profile_erase:tests/test_profile_erase.c src/core/state.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c:-Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led"
    "test_hmac:tests/test_hmac.c::-Isrc/core"
    "test_pin_token_scrub:tests/test_pin_token_scrub.c::"
)

echo "=== Running Fjaeger Host Tests ==="
echo ""

FAILED=()
PASSED=()

for test_spec in "${TESTS[@]}"; do
    IFS=':' read -r name sources libs includes <<< "$test_spec"

    echo -n "Building $name... "

    # Build command
    BUILD_CMD="cc -std=c11 -Wall -Wextra -Werror"
    if [ -n "$includes" ]; then
        BUILD_CMD="$BUILD_CMD $includes"
    fi
    if [ -n "$libs" ]; then
        BUILD_CMD="$BUILD_CMD $libs"
    fi
    BUILD_CMD="$BUILD_CMD $sources -o /tmp/fjaeger-$name"

    if $BUILD_CMD 2>&1 | grep -q error; then
        echo "FAILED (build)"
        FAILED+=("$name (build)")
        continue
    fi
    echo "ok"

    echo -n "Running $name... "
    if ! /tmp/fjaeger-$name > /tmp/fjaeger-$name.log 2>&1; then
        echo "FAILED"
        cat /tmp/fjaeger-$name.log
        FAILED+=("$name")
    else
        # Extract the final "ok" line
        RESULT=$(tail -1 /tmp/fjaeger-$name.log)
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
