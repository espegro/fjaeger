# Fjaeger

A USB security key based on the **RP2350** (16 MB flash). It combines a
**FIDO2/CTAP2 authenticator for SSH** with a small **encrypted USB drive**,
controlled over a serial command interface.

## Features

- **CTAP2 (FIDO2) over HID** — `authenticatorGetInfo`, `makeCredential`,
  `getAssertion`, `getNextAssertion`, `authenticatorClientPIN` and
  `authenticatorCredentialManagement`, encoded in CBOR, for WebAuthn and
  OpenSSH `sk-ecdsa` keys. Attestation uses the `none` format.
- **Resident (discoverable) keys** — full end-to-end support verified with
  OpenSSH: `ssh-keygen -t ecdsa-sk -O resident`, `ssh-keygen -K` (download),
  signing and verification.
- **Profiles** — up to 8 named profiles. A profile is an access filter over
  CTAP2 credentials: only credentials in the selected profile can be discovered
  or used, and new credentials are bound to the selected profile automatically.
  Choose a profile over serial with `PROFILE SELECT <id>`.
- **Encrypted USB drive (MSC)** — a persistent **12 MiB FAT16** partition in
  on-board flash, encrypted with AES-XTS using a **dedicated disk key** that is
  independent of profiles. It is only mounted while the device is unlocked.
  Data survives reboot.
- **Lock/unlock model** — when locked, signing, decryption and writing are
  denied. Unlocking requires the PIN over serial.
- **Brute-force protection** — the device PIN and disk PIN lock after five wrong
  attempts. A shared recovery PUK can clear the lock; five wrong PUK attempts
  trigger a factory wipe.
- **Serial console (USB CDC)** — `LOCK`, `UNLOCK`, `SETPIN`, `RESET BOOTSEL`,
  `TIMEOUT`, profile management, and more.

## Hardware

- Raspberry Pi RP2350 (16 MB flash, `waveshare_rp2350_plus_16mb` board profile)
- Integrated USB-A plug
- Addressable RGB LED on GPIO22: red = locked, green = unlocked, yellow = not
  enumerated, blue pulse = USB activity. Brief pulses signal security events: a
  green flash on a successful PIN unlock, a red flash on lock, and a cyan flash
  when an SSH key signs.

## Architecture

```
src/
├── main.c                  Entry point, init, main loop
├── core/
│   ├── state.h/.c          State machine (LOCKED/UNLOCKED), PIN, auto-relock
│   ├── keys.h/.c           Profiles, flash storage, active profile
│   └── crypto.h/.c         mbedTLS wrappers: ECDSA, SHA-256, HKDF, AES-XTS,
│                           ECDH, AES-CBC, HMAC-SHA256
├── fido/
│   ├── u2f.h/.c            CTAPHID transport (legacy CTAP1/MSG disabled)
│   ├── ctap2.h/.c          CTAP2 commands (makeCredential/getAssertion/
│   │                       getInfo/getNextAssertion/credential management)
│   ├── pin.h/.c            authenticatorClientPIN (PIN/UV auth protocol 1)
│   └── cbor.h/.c           Minimal CBOR encoder/decoder
├── led/
│   ├── rgb_led.c/.h        Status LED on GPIO22
│   └── rgb_led.pio         WS2812/SK6812 PIO program
└── usb/
    ├── tusb_config.h       TinyUSB config (CDC + HID + MSC)
    ├── usb_descriptors.c   Composite descriptors
    ├── msc_disk.c/.h       Encrypted MSC drive
    └── cdc_console.c/.h    Serial command interface
```

### Security model

- Private keys are stored in RP2350 flash and only ever used for signing inside
  the firmware; they are never exported over serial.
- **Device lock** (`LOCK`/`UNLOCK`): when locked, no ECDSA signing happens.
  Unlock with the PIN over serial.
- **Disk lock** (`DISK LOCK`/`DISK UNLOCK`): the encrypted MSC drive is only
  mounted/readable/writable after `DISK UNLOCK`. `DISK UNLOCK` requires the
  device to be unlocked; `LOCK` and auto-relock also close the drive.
- The MSC drive uses a **dedicated permanent XTS key** stored in the flash
  store, independent of profiles. Switching or deleting profiles does not change
  drive data.
- The device PIN, disk PIN and recovery PUK are derived with salted
  PBKDF2-HMAC-SHA256 (a fresh random salt per field), so a dumped flash store
  cannot be brute-forced offline with a fast hash. The disk key is wrapped with
  the PBKDF2-derived disk-PIN key. The CTAP2 client-PIN verifier is
  `LEFT(SHA-256(pin),16)` because the CTAP2 PIN protocol only transmits that
  value. PBKDF2 runs in the main loop and takes a couple of seconds on the
  RP2350.
- The SSH/CTAP2 credential private keys are stored in flash **in clear** (only
  the disk key is wrapped). A physical attacker who dumps flash gets the SSH
  keys regardless of the PIN; the PIN protects the device lock and the disk
  key.
- The device PIN and disk PIN have separate, persistent failure counters. A PUK
  clears a disk-PIN lock but does not replace the disk PIN: the disk key is
  still wrapped by the correct disk PIN.

> **Note:** the RP2350 has no real hardware secure element (unlike an
> ATECC608B). Secure boot exists, but protection against a physical attacker
> with lab equipment is limited. This is a prototype/development platform, not
> a certified production security key.

## Building

Prerequisites: CMake ≥ 3.13, ARM-none-EABI toolchain, **Pico SDK ≥ 2.1.0**
(preferably 2.2.0) and **`picotool`** on PATH (for flashing). The host tests
only need `cc` (x86-64).

The dongle is a **TENSTAR RP2350-USB 16 MB** and uses the board profile
`waveshare_rp2350_plus_16mb` (electrically compatible). It builds against
Pico SDK 2.2.0 (with TinyUSB that supports RP2350).

```bash
# Use SDK 2.2.0 (required for RP2350 USB support)
cmake -S . -B build \
  -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

Result: `build/fjaeger.uf2`. Put the dongle into BOOTSEL mode and flash with
one of the scripts. The device also accepts the console command
`RESET BOOTSEL` to enter BOOTSEL mode programmatically.

```bash
scripts/reflash.sh            # firmware only; drive + store (profiles/PIN) kept
scripts/reflash_wipe.sh       # erase all flash (firmware + drive + store), then flash
```

### Do you lose your keys when re-flashing the firmware?

**No — not with a normal firmware flash.** `scripts/reflash.sh` writes only the
firmware and **preserves** the flash store (profiles, PIN, PUK, CTAP2
credentials and the disk key), so all your keys survive.

You lose your keys only when one of these happens:

- **`scripts/reflash_wipe.sh`** — erases the whole 16 MB flash (firmware +
  drive + store) before flashing.
- **A `STORE_VERSION` bump in the firmware source** — during development the
  on-flash format version is bumped without migration, so existing data is
  treated as incompatible and discarded on the next boot.
- **A console factory wipe** — five wrong PUK attempts erase all profiles,
  credentials and the disk key.

> For a production device you would bump `STORE_VERSION` only with a real
> migration path. During development, assume a firmware flash preserves keys but
> a version bump may discard them.

**Flash layout:** firmware ~128 KB from `0x10000000`, a 12 MiB drive partition
from `0x10100000`, and the store (PIN/profiles/CTAP2/disk key) in the last
8 KiB. A normal firmware flash touches neither the drive nor the store; only a
full erase removes them.

## Serial commands

Connect to the console (e.g. `screen /dev/ttyACM0 115200`):

| Command | Description |
|---------|-------------|
| `HELP` | List commands |
| `STATUS` | Show device + drive state, active profile, profiles, timeout |
| `LOCK` | Lock the device (and close the drive) |
| `UNLOCK <pin>` | Unlock the **device** for key operations (not the drive) |
| `SETPIN <pin>` | Set/change PIN |
| `UNLOCKPUK <puk>` | Unblock a locked device PIN with the recovery PUK |
| `PUK <code>` | Set/change the recovery PUK |
| `DISK SETPIN <pin>` | Set/change the disk PIN |
| `DISK UNLOCK <pin>` | Unlock/mount the encrypted drive (separate step) |
| `DISK UNBLOCK <puk>` | Clear the disk-PIN lock; the correct disk PIN is still required |
| `DISK LOCK` | Lock/unmount the drive |
| `DISK STATUS` | Show drive state |
| `PROFILE LIST` | Show all profiles, active marker and credential count |
| `PROFILE CREATE <id> <name>` | Create a new empty profile |
| `PROFILE SELECT <id>` | Select and persist the active profile |
| `PROFILE RENAME <id> <name>` | Rename without changing credentials |
| `PROFILE ERASE <id>` | Delete the profile and all its credentials |
| `TIMEOUT <seconds>` | Set auto-relock delay (default 900 seconds; 0 = off) |
| `RESET` | Reboot the device |
| `RESET BOOTSEL` | Reboot into the USB bootloader (for flashing) |

> **Independent disk lock:** `UNLOCK <pin>` only unlocks the **device** (for
> FIDO/SSH signing). The encrypted drive is a separate step: `DISK UNLOCK`.
> `LOCK` and auto-relock also close the drive, and `DISK UNLOCK` requires the
> device to be unlocked.

Auto-lock defaults to 15 minutes. The `TIMEOUT` value is stored in the flash
store and survives both reboot and a normal firmware flash. `TIMEOUT 0` is
stored as an explicit disable.

The console does not echo commands. Turn off local echo in your terminal too;
the firmware clears its command buffer after each command but cannot erase text
that the terminal has already displayed or logged.

## SSH (sk-keys)

The dongle is a CTAP2 authenticator with ECDSA P-256 keys, so it is used with
**`sk-ecdsa-sha2-nistp256@openssh.com`** — **not** `ed25519-sk` (the device has
no EdDSA key). The device must be **unlocked** (PIN over serial) and the
**correct profile selected** before credential operations are allowed.

### How the key model works

- **The private key lives only in the dongle**, never on the PC. The PC holds
  only the credential ID + public key.
- **A profile is the access filter**: the dongle refuses to use credentials
  outside the active profile. The SSH file may point at the same credential ID,
  but it only works when the correct profile is selected.
- A profile is **not** a shared key — each credential has its own random
  P-256 key.
- CTAP2 credentials are stored in flash (up to 8) in a CRC-checked A/B format,
  written defer-ably from the main loop. Attestation is `none`. Deleting a
  profile makes its credentials unusable; a factory wipe (5 wrong PUKs) deletes
  all profiles and credentials.

### Create a non-resident key

```bash
# 1. Unlock the dongle and select a profile on the console:
#    UNLOCK <pin>  and  PROFILE SELECT <id>
# 2. Find the FIDO device (e.g. /dev/hidraw2) and generate the key:
ssh-keygen -t ecdsa-sk -O device=/dev/hidraw2 \
  -f ~/.ssh/id_ecdsa_sk -N '' -C fjaeger-test
```

This sends `makeCredential` (CTAP2) to the dongle, which:
1. generates a **random P-256 private key** that **never leaves the device**;
2. stores it in flash with a `credential_id` and `rp_id_hash` (SHA-256 of the
   RP, here `ssh:`), **bound to the active profile**;
3. returns only the `credential_id` + public key to the PC.

The result is `~/.ssh/id_ecdsa_sk` (credential ID + public key) and
`~/.ssh/id_ecdsa_sk.pub`. Put the `.pub` in the host's `authorized_keys`.

### Create a resident (discoverable) key

```bash
ssh-keygen -t ecdsa-sk -O resident -O device=/dev/hidraw2 \
  -f ~/.ssh/id_ecdsa_sk -N '' -C fjaeger-test
```

Resident keys are stored on the authenticator itself, so you can recover them
onto any PC without keeping the key file. You will be prompted for the dongle's
PIN (this is the CTAP2 client-PIN flow; on a device with no PIN set, any PIN is
accepted).

Download resident keys from the dongle:

```bash
ssh-keygen -K
```

`-K` enumerates the discoverable credentials of the **active profile** (via
`authenticatorCredentialManagement`) and rebuilds the private key files in the
current directory. Only the credential handle and public key are exported — the
private key never leaves the device.

### How a key signs (authentication)

On login, OpenSSH sends `getAssertion` with the credential ID in an allowList.
The dongle:
1. **verifies the credential is in the active profile** — if the wrong profile
   is selected, signing is denied even though the PC has the right key file;
2. signs `authData || clientDataHash` with the stored private key;
3. returns the DER signature to the PC, which forwards it to the host.

```bash
ssh -i ~/.ssh/id_ecdsa_sk -o ControlPath=none user@host
```

Use `-o ControlPath=none` when testing — `ControlMaster`/multiplexing in
`~/.ssh/config` can reuse an existing connection without re-authenticating and
thereby mask the profile isolation.

### Verify a signature without SSH login

```bash
ssh-keygen -Y sign -f id_ecdsa_sk -n test file.txt      # creates file.txt.sig
ssh-keygen -Y verify -f allowed_signers -I <name> -n test -s file.txt.sig < file.txt
```

`allowed_signers` must be of the form
`name sk-ecdsa-sha2-nistp256@openssh.com <base64 key>`.

## Status / known limitations

- **Legacy U2F/CTAP1 is disabled.** The device advertises CTAPHID `NMSG` until
  (if ever) the CTAP1 code is replaced with a full implementation.
- **CTAP2** implements `authenticatorGetInfo`, `makeCredential`,
  `getAssertion`, `getNextAssertion`, `authenticatorClientPIN` and
  `authenticatorCredentialManagement` with `none` attestation. Parsers and
  response formats have host tests; OpenSSH enrollment, signing, verification,
  resident-key download (`ssh-keygen -K`) and real SSH login are physically
  tested on the RP2350 dongle.
  - Only **ECDSA P-256 / ES256** is supported (no EdDSA/ed25519-sk).
  - The device must be unlocked (PIN) for `makeCredential`/`getAssertion` to be
    accepted.
  - Credentials are flash-persistent (up to 8) in a CRC-checked A/B format,
    written defer-ably from the main loop.
  - The CTAP2 client PIN reuses the device's global PIN: with no PIN set any
    PIN is accepted (so `ssh-keygen -K` works on a fresh device); with a PIN
    set it is verified.
- The MSC drive is a **12 MiB persistent FAT16 partition** in on-board flash,
  encrypted on the fly with AES-XTS using a **dedicated disk key** (independent
  of profiles). Metadata (boot, FAT, root) is initialized once on first boot;
  the data region is written lazily. Data survives reboot.
  - **Deferred write-behind:** USB MSC callbacks queue sector writes; the
    actual flash erase/program happens in the main loop (`fj_msc_task`), never
    inside a USB transaction. Data flushes on `LOCK`/unmount and continuously.
  - **Integrity:** a persistent CRC-32 table (one per 4 KiB block, stored in
    cleartext in the last blocks of the partition) is verified on mount.
    Corruption from power loss or tampering is detected and the drive is
    re-initialized instead of serving corrupt data.
  - Writing large files is slow and wears flash, because every sector update
    requires a flash erase.

## License

BSD-3-Clause.