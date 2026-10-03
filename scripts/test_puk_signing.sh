#!/usr/bin/env bash
# Test that credential signing works after PUK unlock.
#
# This script automates the manual test in tests/MANUAL_TEST_PUK_SIGNING.md.
# It requires a connected Fjaeger device and will WIPE it first.
#
# Usage: scripts/test_puk_signing.sh [serial_port] [hid_device]
#
# Example: scripts/test_puk_signing.sh /dev/ttyACM0 /dev/hidraw2
set -euo pipefail

SERIAL="${1:-/dev/ttyACM0}"
HID="${2:-/dev/hidraw2}"
TESTKEY="/tmp/fjaeger_puk_test_key"

cd "$(dirname "$0")/.."

echo "=== Fjaeger PUK Signing Test ==="
echo "Serial: $SERIAL"
echo "HID:    $HID"
echo ""

# Check prerequisites
command -v ssh-keygen >/dev/null || { echo "error: ssh-keygen not found"; exit 1; }
command -v picotool >/dev/null || { echo "error: picotool not found"; exit 1; }
[ -c "$SERIAL" ] || { echo "error: serial port $SERIAL not found"; exit 1; }
[ -c "$HID" ] || { echo "error: HID device $HID not found"; exit 1; }

echo "WARNING: This will WIPE the device (all credentials + keys)."
read -r -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

# Wipe and reflash
echo ""
echo "Step 1: Wiping device and reflashing firmware..."
echo "YES" | scripts/reflash_wipe.sh

echo "Waiting for device to reboot..."
sleep 3

# Helper: send command to serial and wait for response
serial_cmd() {
    # This is a simplified version - a real implementation would use
    # expect or pyserial for proper serial interaction
    echo "TODO: implement serial command automation"
    echo "  Would send: $1"
}

echo ""
echo "==================================================================="
echo "MANUAL STEPS REQUIRED (automation TODO):"
echo "==================================================================="
echo ""
echo "Connect to $SERIAL with: screen $SERIAL 115200"
echo ""
echo "Then run these commands:"
echo ""
echo "1. Setup PIN and PUK:"
echo "   fjaeger> SETPASS test-pass-123"
echo "   fjaeger> UNLOCK test-pass-123"
echo "   fjaeger> PUK test-puk-456789"
echo ""
echo "2. Leave screen (Ctrl-A, K) and create a credential:"
echo "   ssh-keygen -t ecdsa-sk -O resident -O device=$HID \\"
echo "     -f $TESTKEY -N '' -C puk-test"
echo ""
echo "3. Reconnect to serial and block PIN:"
echo "   fjaeger> LOCK"
echo "   fjaeger> UNLOCK wrong1  # Repeat 5 times with different wrong passwords"
echo "   fjaeger> UNLOCK wrong2"
echo "   fjaeger> UNLOCK wrong3"
echo "   fjaeger> UNLOCK wrong4"
echo "   fjaeger> UNLOCK wrong5"
echo "   # Should now see: ERR passphrase blocked"
echo ""
echo "4. Unlock with PUK:"
echo "   fjaeger> UNLOCKPUK test-puk-456789"
echo "   # Should see: OK unlocked via PUK"
echo "   fjaeger> STATUS"
echo "   # Should show: state: unlocked"
echo ""
echo "5. Leave screen and test signing:"
echo "   echo 'test message' > /tmp/test.txt"
echo "   ssh-keygen -Y sign -f $TESTKEY -n test /tmp/test.txt"
echo ""
echo "   ✓ SUCCESS: If you see cyan LED flash and test.txt.sig is created"
echo "   ✗ FAILURE: If you see 'agent refused operation'"
echo ""
echo "6. Verify signature:"
echo "   echo \"testkey \$(cat $TESTKEY.pub)\" > /tmp/allowed_signers"
echo "   ssh-keygen -Y verify -f /tmp/allowed_signers -I testkey \\"
echo "     -n test -s /tmp/test.txt.sig < /tmp/test.txt"
echo ""
echo "   ✓ SUCCESS: Should see 'Good \"test\" signature'"
echo ""
echo "==================================================================="
echo ""
echo "NOTE: Full automation requires expect or pyserial for serial I/O."
echo "See tests/MANUAL_TEST_PUK_SIGNING.md for detailed procedure."
