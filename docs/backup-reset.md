# Backup, restore and factory reset

## What the backup contains

`BACKUP <password>` writes an encrypted `FJAEGER.BAK` containing the credential
master key, profile and ordinary credential data, and the separate hmac root
and credentials when initialized. It is **not a disk backup**: it does not
contain the USB drive's files, its disk encryption key, or the CTAP2 PIN. Copy
important drive files separately. Keep backups and their passwords secure;
deleting a credential from the device does not delete its backup copies.

Unlock the device and disk, then run `BACKUP <password>`. Copy `FJAEGER.BAK`
to a secure location before locking: the device deletes that temporary file
when the drive locks. If the host does not show the file, flush and unmount the
volume and remount it while the drive remains unlocked. Do not format the drive.
Avoid logging commands containing passwords.

To restore, prepare and unlock the target device and its disk, copy the backup
onto the drive as `FJAEGER.BAK`, flush host writes, then run
`RESTORE <backup-password> <new-passphrase> <new-puk>`. The restore replaces
credential/profile material and sets the new device passphrase and PUK; it does
not restore disk files, disk key, or CTAP2 PIN. A combined hmac backup requires
the target hmac store to have been initialized in the same root protection mode
(currently development mode). Set its FIDO PIN and use `HMAC init` with BOOT
first. The device locks after combined restore. Legacy backups have different
compatibility restrictions. This workflow was tested on one development board,
not on replacement hardware; verify recovery before relying on it.

## Factory reset

Before reset, copy the backup and disk files elsewhere and verify access to any
LUKS recovery keys. A backup cannot recover the old disk encryption key.

1. Unlock Fjaeger with its existing passphrase.
2. Send `FACTORY RESET YES`, or choose factory reset in the TUI and confirm.
3. When prompted, **press and release BOOT within 30 seconds**. A stale press
   does not count; cancellation, disconnect or locking interrupts confirmation.
4. Wait for the completion message. The device is now unconfigured and locked;
   use the [setup guide](getting-started.md) to configure it again.

Reset erases credentials, profiles, passphrase, PINs, PUK, hmac material,
configuration and disk encryption key. The encrypted disk data region remains
in flash but is inaccessible without the erased key. Firmware, OTP and external
backups are untouched. This is not a physical erase of all flash. Five wrong
PUK attempts also trigger a wipe. `RESET` only reboots; `RESET BOOTSEL` enters
the bootloader. `scripts/reflash_wipe.sh` erases the whole flash before
reflashing and is a separate, destructive operation.
