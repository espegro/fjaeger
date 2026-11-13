# Experimental hmac-secret and LUKS

The hmac store is separate from profile credentials, supports eight entries,
and can operate while the device is locked. Its development root resides in
ordinary flash; Secure Boot and hardware root protection are not implemented.
Do not use this as the only unlock method for important data. CTAP2 PIN
verifiers permit fast offline guessing if flash is dumped.

## Setup and policy

Unlock the device, configure a FIDO PIN with `SETPIN`, then issue `HMAC init`
and press and release BOOT when requested. Enrollment of an hmac credential
also requires an unlocked device and a fresh BOOT confirmation. A FIDO PIN is
required to initialize, but registration may proceed without the client sending
one; if the client supplies a PIN it must verify.

Every policy change requires the unlocked device and fresh BOOT confirmation:

| Command | Subsequent hmac-secret use |
| --- | --- |
| `HMAC pin-button` | FIDO PIN and a fresh BOOT press per request (initial policy). |
| `HMAC pin` | Verified FIDO PIN, no BOOT press. |
| `HMAC auto` | No PIN or BOOT; a connected device can supply the secret while locked. |
| `HMAC armed` | No PIN after a BOOT press arms the device; arming is lost on MCU reboot or loss of power. |

`pin`, `auto` and `armed` deliberately allow assertions without user presence
(UP=0), a CTAP compatibility deviation. PIN mode reports UV=1 after PIN
verification. A PIN-mode preflight may identify and sign with an RP-bound
credential without PIN or UP, but does not return the hmac-secret. Switching
between verified and unverified policies may change the derived secret: keep a
working recovery key and re-enroll the LUKS token for the intended policy.

## Disposable LUKS2 demonstration

This example creates a **new temporary file**, not a disk. It requires Linux,
`cryptsetup`, `systemd-cryptenroll`, permissions for the FIDO device and a
compatible systemd/cryptsetup build. It demonstrates `auto`, which does not
require a PIN or BOOT for subsequent unlocks. For real data, independently
validate your boot/initramfs workflow and recovery procedures first.

```bash
umask 077
FJ_TEST_DIR=$(mktemp -d)
head -c 64 /dev/urandom > "$FJ_TEST_DIR/recovery.key"
truncate -s 64M "$FJ_TEST_DIR/luks.img"
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$FJ_TEST_DIR/recovery.key" "$FJ_TEST_DIR/luks.img"
systemd-cryptenroll --fido2-device=list
```

Unlock Fjaeger, initialize hmac if needed, select `HMAC auto` and confirm BOOT.
Set `FJ_FIDO_DEVICE` below to its path from the listing. Enrollment prompts for
another fresh BOOT press on the device. Keep the recovery key safe.

```bash
FJ_FIDO_DEVICE=/dev/hidrawX  # replace with the listed device
systemd-cryptenroll --unlock-key-file="$FJ_TEST_DIR/recovery.key" \
  --fido2-device="$FJ_FIDO_DEVICE" --fido2-with-client-pin=no \
  --fido2-with-user-presence=no --fido2-with-user-verification=no \
  "$FJ_TEST_DIR/luks.img"
cryptsetup open --test-passphrase --token-only "$FJ_TEST_DIR/luks.img"
cryptsetup open --test-passphrase --key-file "$FJ_TEST_DIR/recovery.key" "$FJ_TEST_DIR/luks.img"
```

A successful test checks the passphrase without creating a mapped device. PIN
policy needs a client that supports FIDO PIN and different enrollment flags.
PIN-only, auto and armed have been checked on disposable LUKS files and one
development board; actual boot, initramfs and replacement hardware have not.

## Listing and deleting credentials

Unlock the device and run `HMAC LIST`. It prints credential IDs as hex and RP
ID hashes. The LUKS header records the credential ID and salt; view it with
`cryptsetup luksDump --dump-json-metadata <device-or-file>`. To compare its
`fido2-credential` value with the hex ID:

```bash
printf '%s' '<base64-fido2-credential>' | base64 -d | xxd -p
```

Before deleting, verify that the credential is no longer needed and that an
independent recovery method works. `HMAC DELETE <32-hex-id>` requires a fresh
BOOT press. It does not remove the LUKS token/keyslot or copies in backups.
