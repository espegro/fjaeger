# Development and verification

## Build

The firmware requires CMake, an ARM embedded toolchain, and Pico SDK 2.x with
TinyUSB. See [build instructions](../README.md#building) for the board profile,
SDK setup, firmware output and flashing. A normal firmware flash preserves the
store; a full-flash wipe does not. Prebuilt artifacts correspond to their named
commit and may not contain current changes.

## Tests

Host tests require a C11 compiler and mbedTLS development headers/library
(`libmbedtls-dev` on Debian-family systems):

```bash
bash scripts/run_all_tests.sh
```

The suite covers security state, protocol handling, hmac, backup/restore,
factory confirmation and other components. The terminal controller uses Go:

```bash
cd tui
go test ./...
go build -o fjaeger-tui .
```

Tests with mocks and host libraries do not prove physical security or cover all
hardware timing and power-loss cases. A development board has been used for
hmac PIN, auto and armed checks, backup/restore, and LUKS checks on disposable
files. Actual boot/initramfs, replacement-device restoration and physical
power-cut fault injection remain unverified. Factory reset confirmation has
been checked without executing a destructive reset on the current device.

Secure Boot, OTP provisioning and signed updates are not implemented. Do not
program irreversible device security settings as part of ordinary development.
