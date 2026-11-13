# Getting started

Fjaeger is a development prototype. Keep independent recovery credentials and
avoid relying on it as the sole key to important data. See the security status
in the [README](../README.md).

1. Build and flash the firmware as described in the [README](../README.md#building).
   Normal firmware flashing preserves device data; a full flash erase does not.
2. Connect the CDC serial port, for example `screen /dev/ttyACM0 115200`, or
   use the [TUI](../tui/README.md). Only one application can use the port at a
   time. Check device permissions and close other serial programs if necessary.
3. Send `HELP` and `STATUS`. The console accepts commands without their secret
   argument and prompts for the secret. Disable local terminal echo and logging;
   the device masks interactive secret input.
4. On an unconfigured device, use `SETPASS`, then `UNLOCK`. Set a recovery
   secret with `PUK` and a separate FIDO PIN with `SETPIN`. Record your recovery
   secret securely. These are separate secrets with separate purposes.
5. For the encrypted USB drive, use `DISK SETPIN` and `DISK UNLOCK`. The disk
   PIN is separate from the device passphrase. Mount the exposed filesystem on
   the host. Flush and unmount it before `DISK LOCK` or `LOCK`.
6. Use `PROFILE LIST`, `PROFILE CREATE`, `PROFILE SELECT` and `CREDS LIST` for
   ordinary FIDO/SSH credentials. `HELP SSH` explains enrollment. `HELP HMAC`
   explains the separate experimental hmac store.

`LOCK` and automatic timeout also close the disk. `PRESENCE button` requires a
fresh BOOT press for ordinary FIDO operations; see `HELP` for changing it back.
Use `STATUS` to check the current state. For hmac and LUKS, follow the separate
[hmac guide](hmac-luks.md); for recovery and reset see [backup and reset](backup-reset.md).
