#!/usr/bin/env bash
# Flash the latest built firmware, preserving keys/profiles
set -euo pipefail

cd "$(dirname "$0")/.."

UF2="build/fjaeger.uf2"
VERSION=$(git describe --always --tags --dirty)

echo "=== Fjaeger Flash Latest ==="
echo "Version: $VERSION"
echo "Firmware: $UF2"
echo ""

# Check if firmware exists
if [ ! -f "$UF2" ]; then
    echo "ERROR: $UF2 not found"
    echo "Run: cmake --build build -j\$(nproc)"
    exit 1
fi

# Show firmware info
SIZE=$(du -h "$UF2" | cut -f1)
echo "Size: $SIZE"
echo ""

# Check if device is in BOOTSEL mode
echo "Checking for RP2350 device in BOOTSEL mode..."
if ! picotool info &>/dev/null; then
    echo ""
    echo "No device found in BOOTSEL mode."
    echo ""
    echo "To enter BOOTSEL mode:"
    echo "  Option 1: Connect to serial and run: RESET BOOTSEL"
    echo "  Option 2: Hold BOOTSEL button and connect USB"
    echo ""
    read -p "Press ENTER when device is ready, or Ctrl-C to abort..."

    # Check again
    if ! picotool info &>/dev/null; then
        echo "ERROR: Still no device found."
        exit 1
    fi
fi

echo ""
picotool info | head -15
echo ""

echo "This will flash firmware ONLY (keys and profiles preserved)."
read -p "Continue? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Flashing $UF2..."
picotool load -f "$UF2"

echo "Rebooting device..."
picotool reboot

echo ""
echo "✓ Flash complete (version $VERSION)"
echo ""
echo "The device should now restart with the new firmware."
echo "Keys, profiles, and disk data are preserved."
echo ""
echo "To verify: connect to serial and run 'STATUS'"
