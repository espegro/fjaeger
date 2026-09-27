#!/usr/bin/env bash
# Re-flash the firmware AND wipe all of flash (factory reset at the flash
# level).
#
# This erases the whole 16 MB flash: firmware, the 12 MiB MSC disk partition
# (0x10100000-0x10D00000) and the 8 KiB store at the end (0x10FFE000-
# 0x11000000). Disk data, profiles, PIN, PUK and CTAP2 credentials are all
# destroyed. The firmware is then written fresh; on first boot the device
# recreates an empty "Default" profile.
#
# Usage:  scripts/reflash_wipe.sh [device]
set -euo pipefail

cd "$(dirname "$0")/.."

UF2="build/fjaeger.uf2"
[ -f "$UF2" ] || { echo "error: $UF2 not found; build first (cmake --build build)"; exit 1; }
command -v picotool >/dev/null || { echo "error: picotool not found"; exit 1; }

echo "WARNING: this erases ALL of flash (firmware + disk + profiles/keys)."
read -r -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

echo "Erasing entire flash (firmware + disk + store)..."
picotool erase --all "$@"

echo "Flashing firmware: $UF2"
picotool load -f "$UF2" "$@"
picotool reboot "$@"
echo "Done. Device wiped and rebooted into application mode."