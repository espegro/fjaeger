#!/usr/bin/env bash
# Re-flash only the firmware, preserving the MSC disk partition and the
# profile/key store.
#
# This writes only the firmware binary (build/fjaeger.uf2). The 12 MiB disk
# partition (0x10100000-0x10D00000) and the 8 KiB store at the end of flash
# (0x10FFE000-0x11000000) are left untouched, so disk data, profiles, PIN,
# PUK and CTAP2 credentials survive the flash.
#
# Usage:  scripts/reflash.sh [device]
set -euo pipefail

cd "$(dirname "$0")/.."

UF2="build/fjaeger.uf2"
[ -f "$UF2" ] || { echo "error: $UF2 not found; build first (cmake --build build)"; exit 1; }
command -v picotool >/dev/null || { echo "error: picotool not found"; exit 1; }

echo "Flashing firmware only: $UF2 (disk + store preserved)"
picotool load -f "$UF2" "$@"
picotool reboot "$@"
echo "Done. Device rebooted into application mode."