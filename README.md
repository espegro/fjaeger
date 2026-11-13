# Fjaeger

A USB security key based on the **RP2350** (16 MB flash). It combines a
**FIDO2/CTAP2 authenticator for SSH** with a small **encrypted USB drive**,
controlled over a serial command interface.

> **Development prototype:** Secure Boot and hardware-protected hmac roots are
> not implemented. The experimental hmac policies can permit operation while
> the device is locked. Do not rely on this device as the only way to unlock
> important data.

## Documentation

- [Getting started](docs/getting-started.md): initialize and use a device.
- [hmac-secret and LUKS](docs/hmac-luks.md): policies, enrollment and credential management.
- [Backup and factory reset](docs/backup-reset.md): recovery scope and reset procedure.
- [Development](docs/development.md): builds, tests and hardware verification.
- [Terminal controller](tui/README.md): optional Go TUI.

## Features

- **CTAP2 (FIDO2) over HID** — `authenticatorGetInfo`, `makeCredential`,
  `getAssertion`, `getNextAssertion`, `authenticatorClientPIN` and
  `authenticatorCredentialManagement`, encoded in CBOR, for WebAuthn and
  OpenSSH `sk-ecdsa` and `sk-ed25519` keys. Attestation uses the `none` format.
- **Resident (discoverable) keys** — full end-to-end support verified with
  OpenSSH: `ssh-keygen -t ecdsa-sk -O resident`, `ssh-keygen -K` (download),
  signing and verification.
- **Profiles** — up to 16 named profiles. A profile is an access filter over
  CTAP2 credentials: only credentials in the selected profile can be discovered
  or used, and new credentials are bound to the selected profile automatically.
  Choose a profile over serial with `PROFILE SELECT <id>`.
- **Encrypted USB drive (MSC)** — a persistent **12 MiB FAT16** partition in
  on-board flash, encrypted with AES-XTS using a **dedicated disk key** that is
  independent of profiles. It is only mounted while the device is unlocked.
  Data survives reboot.
- **Lock/unlock model** — ordinary profile credentials and the drive require the device
  to be unlocked. Separate hmac credentials follow their own policy and may
  operate while locked. Unlocking uses the device passphrase over serial.
- **Brute-force protection** — the unlock passphrase and disk PIN lock after five wrong
  attempts. A shared recovery PUK can clear the lock; five wrong PUK attempts
  trigger a factory wipe. Failed attempts are also paced by an exponential
  backoff delay.
- **Key protection at rest** — every credential private key is encrypted with a
  master key M that is wrapped by both the PIN and the PUK, so a PUK recovery
  can set a new PIN without losing keys.
- **Encrypted backup/restore** — `BACKUP <password>` writes an encrypted
  `FJAEGER.BAK` to the MSC drive; `RESTORE <password> <pin> <puk>` restores it
  subject to the prerequisites and limitations in the [backup guide](docs/backup-reset.md).
- **Serial console (USB CDC)** — `LOCK`, `UNLOCK`, `SETPIN`, `RESET BOOTSEL`,
  `TIMEOUT`, profile management, and more.

> **POC protocol scope:** CTAP2 ClientPIN supports retry reporting, key
> agreement and token retrieval for the OpenSSH flow. PIN creation/change is
> intentionally administered through the CDC `SETPIN` command rather than the
> CTAP2 `setPIN`/`changePIN` subcommands. Global device unlock is the user
> authorization boundary. `credProtect` is advertised for OpenSSH resident-key
> compatibility but its UV policies are not enforced by this POC.

## Hardware

- Raspberry Pi RP2350 (16 MB flash, `waveshare_rp2350_plus_16mb` board profile)
- Integrated USB-A plug
- Addressable RGB LED on GPIO22: **yellow blink = no credential enrolled**
  (blank/unprovisioned device, shown regardless of lock state), **red blink =
  locked (provisioned)**, **green = unlocked (provisioned)**, amber = not
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
- **Device lock** (`LOCK`/`UNLOCK`): ordinary profile credentials require
  the device to be unlocked. Separate hmac credentials have independent policy
  and can sign assertions while locked.
- **Disk lock** (`DISK LOCK`/`DISK UNLOCK`): the encrypted MSC drive is only
  mounted/readable/writable after `DISK UNLOCK`. `DISK UNLOCK` requires the
  device to be unlocked; `LOCK` and auto-relock also close the drive.
- The MSC drive uses a **dedicated permanent XTS key** stored in the flash
  store, independent of profiles. Switching or deleting profiles does not change
  drive data.
- The unlock passphrase, disk PIN and recovery PUK are derived with salted
  PBKDF2-HMAC-SHA256 (a fresh random salt per field), providing slower offline guessing for those secrets. The disk key is wrapped with
  the PBKDF2-derived disk-PIN key. The CTAP2 client-PIN verifier is
  `LEFT(SHA-256(pin),16)` because the CTAP2 PIN protocol only transmits that
  value; a flash dump therefore permits fast offline guessing of the CTAP2 PIN.
  PBKDF2 runs in the main loop and takes a couple of seconds on the
  RP2350.
- The SSH/CTAP2 credential private keys are encrypted **at rest** by a random
  master key M (AES-GCM). M is stored in flash wrapped independently by the
  device PIN and the recovery PUK, so a physical attacker who dumps flash must
  still recover M by guessing a passphrase or PUK (slow, salted PBKDF2). Because the
  PUK can also recover M, a **PUK recovery can set a new PIN without losing
  keys**. A weak PUK therefore weakens at-rest key protection.
- The unlock passphrase, disk PIN and CTAP2 PIN each have separate, persistent failure counters. A PUK
  clears a disk-PIN lock but does not replace the disk PIN: the disk key is
  still wrapped by the correct disk PIN.

> **Note:** the RP2350 has no real hardware secure element (unlike an
> ATECC608B). Secure boot exists, but protection against a physical attacker
> with lab equipment is limited. This is a prototype/development platform, not
> a certified production security key.

## Building

### Prerequisites

- **CMake ≥ 3.13** — e.g. `apt install cmake`.
- **ARM GNU toolchain** (`arm-none-eabi-gcc`) — e.g. `apt install gcc-arm-none-eabi`.
- **Pico SDK ≥ 2.1.0** (preferably **2.2.0**) with RP2350/TinyUSB support.
- **`picotool`** on `PATH` (only needed to flash).
- The host tests need a C11 compiler (`cc`) and mbedTLS development libraries.

The Pico SDK is **not vendored** in this repository. Either clone it next to
this checkout and set `PICO_SDK_PATH`, or let CMake fetch it automatically.

### Get the Pico SDK

Option A — clone next to the checkout (the SDK has its own submodules, e.g.
TinyUSB, so use `--recurse-submodules`):

```bash
git clone --recurse-submodules -b 2.2.0 \
  https://github.com/raspberrypi/pico-sdk.git pico-sdk
```

Option B — let CMake download the SDK automatically on the first configure:

```bash
cmake -S . -B build \
  -DPICO_SDK_FETCH_FROM_GIT=ON \
  -DPICO_SDK_FETCH_FROM_GIT_TAG=2.2.0 \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
```

> Note: `PICO_SDK_FETCH_FROM_GIT` does not fetch TinyUSB with `--recurse
> -submodules`, so if you hit a missing-TinyUSB error, prefer Option A (clone
> with submodules) and point `PICO_SDK_PATH` at it.

### Configure and build

The dongle is a **TENSTAR RP2350-USB 16 MB** and uses the board profile
`waveshare_rp2350_plus_16mb` (electrically compatible with the Waveshare
RP2350-Plus 16 MB). It builds against Pico SDK 2.2.0.

```bash
cmake -S . -B build \
  -DPICO_SDK_PATH=/path/to/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

Result: `build/fjaeger.uf2`.

> **Pre-built firmware:** a ready-to-flash build is committed under
> [`releases/`](releases/) (`fjaeger-<commit>.uf2`, plus the matching `.elf`
> for debugging) so you can flash without building. It is built from the same
> commit as the release. If you built your own, use `build/fjaeger.uf2` from
> that build instead.

### Flash

Put the dongle into **BOOTSEL** mode (hold BOOTSEL, connect USB; or reboot into
it with the console command `RESET BOOTSEL`) and run one of the scripts:

```bash
scripts/reflash.sh            # firmware only; drive + store (profiles/PIN) kept
scripts/reflash_wipe.sh       # erase all flash (firmware + drive + store), then flash
```

To flash the pre-built firmware directly with `picotool` (no build needed):

```bash
# put the dongle in BOOTSEL mode first
picotool load -f releases/fjaeger-582dcb9.uf2
picotool reboot
```

### Host tests

Run `bash scripts/run_all_tests.sh`; see [development](docs/development.md)
for dependencies, firmware builds and hardware test limitations.

### Do you lose your keys when re-flashing the firmware?

**No — not with a normal firmware flash.** `scripts/reflash.sh` writes only the
firmware and **preserves** the flash store (profiles, PIN, PUK, CTAP2
credentials and the disk key), so all your keys survive.

You lose your keys only when one of these happens:

- **`scripts/reflash_wipe.sh`** — erases the whole 16 MB flash (firmware +
  drive + store) before flashing.
- **An incompatible future store format** without a migration path.
- **A factory wipe** — `FACTORY RESET YES` with physical confirmation, or
  five wrong PUK attempts, removes the key material. See [reset](docs/backup-reset.md).

The v17 store migrates a valid v16 store on startup. It validates the new copy
before erasing the old sectors. Do not downgrade to v16 after migration: older
firmware does not understand the new store. Backup v3 supports the expanded
capacity; existing v2 backups remain readable.

**Flash layout:** firmware starts at `0x10000000`, the 12 MiB drive partition
at `0x10100000`, and the store uses two 32 KiB slots at
`0x10FEE000–0x10FFE000`. The last 8 KiB holds the legacy v16 store until
migration. A normal firmware flash touches neither the drive nor the store.

## Serial commands

Connect to the console (e.g. `screen /dev/ttyACM0 115200`):

| Command | Description |
|---------|-------------|
| `HELP` | List commands (`HELP SSH` for SSH usage) |
| `STATUS` | Show device + drive state, active profile, timeout and HMAC configuration |
| `LOCK` | Lock the device (and close the drive) |
| `UNLOCK <passphrase>` | Unlock the **device** for key operations (not the drive) |
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
| `CREDS LIST` | List active-profile credentials with key type, application and ID |
| `CREDS DEL <hex-id> yes` | Delete one credential from the active profile |
| `TIMEOUT <seconds>` | Set auto-relock delay (default 900 seconds; 0 = off) |
| `PRESENCE <auto\|button>` | Select automatic presence or BOOT-button confirmation (device must be unlocked) |
| `HMAC <init\|pin-button\|pin\|auto\|armed>` | Configure experimental development hmac storage and policy |
| `HMAC LIST` | List separate hmac credential IDs and relying-party hashes |
| `HMAC DELETE <hex-id>` | Delete one hmac credential after a fresh BOOT confirmation |
| `BACKUP <password>` | Write an encrypted backup (M + keys + profiles) to `FJAEGER.BAK` |
| `RESTORE <pw> <pin> <puk>` | Restore a backup, setting a new PIN and PUK in one step |
| `RESET` | Reboot the device |
| `RESET BOOTSEL` | Reboot into the USB bootloader (for flashing) |
| `FACTORY RESET YES` | Erase keys and settings after unlock and a fresh BOOT press |

> **Independent disk lock:** `UNLOCK <pin>` only unlocks the **device** (for
> FIDO/SSH signing). The encrypted drive is a separate step: `DISK UNLOCK`.
> `LOCK` and auto-relock also close the drive, and `DISK UNLOCK` requires the
> device to be unlocked.

> **Backup/restore:** The encrypted backup contains profile and credential
> material, including initialized hmac credentials. It is not a disk image and
> does not contain the disk encryption key or CTAP2 PIN. Copy it off the device
> before locking the drive. See the [backup and reset guide](docs/backup-reset.md)
> for restoration prerequisites and limitations.

> **Experimental hmac storage:** `HMAC init` requires an unlocked device, a
> configured FIDO PIN and a fresh BOOT press and release. Its development root
> is stored without hardware protection. Policy changes require the same
> confirmation. FIDO `hmac-secret` is experimental. PIN, auto and armed
> deliberately permit assertions without BOOT and report UP=0. PIN mode requires
> a verified PIN for hmac-secret, but a no-UP preflight can identify and sign
> with the separate RP-bound credential without one. Once initialized,
> backups include the separate store; restoring such a backup currently
> requires a target already initialized in the same development mode and
> leaves the device locked. Backup/restore and disposable LUKS key checks were
> tested on one development device; boot and initramfs remain untested.

`FACTORY RESET YES` requires an unlocked device and a new BOOT press and
release. It erases profiles, FIDO and hmac credentials, PINs, PUK and disk
encryption keys. Encrypted disk data remains in flash but becomes inaccessible;
firmware, OTP and external backups are not erased. `RESET` only reboots.

Each LUKS2 FIDO token records its credential ID and salt in the LUKS header.
Before deleting a credential, compare its hexadecimal ID from `HMAC LIST` with
the decoded `fido2-credential` value in `cryptsetup luksDump --dump-json-metadata`.
Deletion does not remove LUKS keyslots or copies of the credential in backups.

Auto-lock defaults to 15 minutes. The `TIMEOUT` value is stored in the flash
store and survives both reboot and a normal firmware flash. `TIMEOUT 0` is
stored as an explicit disable.

`PRESENCE auto` is the default and retains the existing unlocked-device
behavior. To require a physical confirmation, unlock the device and issue
`PRESENCE button`. The setting is persistent and shown by `STATUS`. A flashing
purple LED requests a fresh BOOT press and release for credential creation, assertions,
and the OpenSSH CTAP1 selection probe; some workflows may ask more than once.
Requests time out after 30 seconds and may be cancelled by the client. To
return to automatic mode, hold BOOT while sending `PRESENCE auto` over the
console. The BOOT press is separate from the device unlock passphrase.

The console echoes input itself, so keep local echo OFF in your terminal
(the terminal would otherwise show secrets in cleartext). Secret entry
(passphrase, PUK, PINs) is masked as `*` and the set/change commands ask for
the value twice to confirm. The firmware wipes its command and secret buffers
after handling, but cannot erase text the terminal has already displayed or
logged.

## SSH (sk-keys)

The dongle supports both **`sk-ecdsa-sha2-nistp256@openssh.com`** (ES256) and
**`sk-ssh-ed25519@openssh.com`** (Ed25519). The device must be **unlocked**
(passphrase over serial) and the **correct profile selected** before credential
operations are allowed.

### How the key model works

- **The private key lives only in the dongle**, never on the PC. The PC holds
  only the credential ID + public key.
- **A profile is the access filter**: the dongle refuses to use credentials
  outside the active profile. The SSH file may point at the same credential ID,
  but it only works when the correct profile is selected.
- A profile is **not** a shared key — each credential has its own random
  P-256 key.
- CTAP2 credentials are stored in flash (up to 64) in a CRC-checked A/B format,
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

# Ed25519 alternative:
ssh-keygen -t ed25519-sk -O device=/dev/hidraw2 \
  -f ~/.ssh/id_ed25519_sk -N '' -C fjaeger-test
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

# Resident Ed25519 alternative:
ssh-keygen -t ed25519-sk -O resident -O device=/dev/hidraw2 \
  -f ~/.ssh/id_ed25519_sk -N '' -C fjaeger-test
```

Resident keys are stored on the authenticator itself, so you can recover them
onto any PC without keeping the key file.

Download resident keys from the dongle:

```bash
ssh-keygen -K -O device=/dev/hidraw2
```

`-K` enumerates the discoverable credentials of the **active profile** (via
`authenticatorCredentialManagement`) and rebuilds the private key files in the
current directory. Only the credential handle and public key are exported — the
private key never leaves the device.

OpenSSH/libfido2 displays `Enter PIN for authenticator:` during `-K` even when
the dongle has no CTAP2 PIN configured. This behaviour was verified on the
physical RP2350 device:

- with no CTAP2 PIN configured, enter any **non-empty** placeholder (for
  example `0000`); Fjaeger accepts it but does not configure or persist it;
- an empty response fails in OpenSSH/libfido2 before discovery completes;
- once a CTAP2 PIN is configured, the entered value must be the correct PIN.

The device must also be globally unlocked, and only resident credentials in
the active profile are returned. A distinct application such as
`-O application=ssh:github` makes the recovered filename descriptive (for
example `id_ed25519_sk_rk_github`).

The same association is visible directly on the serial console:

```text
fjaeger> CREDS LIST
  [00] type=ed25519-sk application=ssh:github resident=yes fp=SHA256:... id=a1b2...
```

For a non-resident credential, Fjaeger stores only the application/RP hash;
`CREDS LIST` therefore reports `application=<not-stored>`. The OpenSSH stub
retains the clear-text application in that case.

### How a key signs (authentication)

This is a CTAP2 challenge-response exchange. OpenSSH sends `getAssertion` with
the RP/application, a fresh `clientDataHash` challenge and (for a non-resident
key) the credential ID in an allowList. The dongle:

1. **verifies the credential is in the active profile** — if the wrong profile
   is selected, signing is denied even though the PC has the right key file;
2. builds `authenticatorData` containing the RP hash, flags and sign counter;
3. signs `authenticatorData || clientDataHash` with the stored private key;
4. returns the signature to the PC, which verifies it with the public key and
   forwards the result to the host. ES256 uses DER encoding; Ed25519 returns
   its raw 64-byte signature.

Fjaeger does not expose a separate custom serial challenge-response command;
the supported challenge-response interface is CTAP2/FIDO2 (and therefore
OpenSSH's security-key protocol).

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

## Testing

### Host tests

Six host tests compile the firmware sources with stubs and run on x86-64:

```bash
scripts/run_all_tests.sh
```

Tests cover:
- Security: PIN/PUK recovery, lockout, factory wipe
- CTAP2: CBOR parsing, makeCredential, getAssertion, resident keys
- Profiles: isolation, credential binding, cache consistency
- Crypto: PBKDF2/HMAC-SHA256 against RFC vectors
- Security scrubbing: pin_token and auth_priv secure-zero on reset

### Device verification

After flashing, verify the device responds:

```bash
scripts/check_device.py
```

Shows version, lock state, profiles, and PUK status via serial.

### Manual hardware testing

For end-to-end PUK unlock and signing verification:

```bash
# See detailed procedure in:
tests/MANUAL_TEST_PUK_SIGNING.md

# Semi-automated test (requires manual serial steps):
scripts/test_puk_signing.sh
```

Verifies that credentials can be decrypted and signed after PUK unlock recovers
the master key M.

### Security review

A comprehensive security analysis is documented in `SECURITY_REVIEW.md`,
covering authentication logic, credential wrapping key management, and known
limitations.

## Status / known limitations

- **Legacy U2F/CTAP1 is incomplete.** Only VERSION and the REGISTER selection
  probe are supported; full CTAP1 registration and authentication are unavailable.
- **CTAP2** implements `authenticatorGetInfo`, `makeCredential`,
  `getAssertion`, `getNextAssertion`, `authenticatorClientPIN` and
  `authenticatorCredentialManagement` with `none` attestation. Parsers and
  response formats have host tests; OpenSSH enrollment, signing, verification,
  resident-key download (`ssh-keygen -K`) and real SSH login are physically
  tested on the RP2350 dongle.
  - **ECDSA P-256 / ES256** and **Ed25519 / EdDSA** credentials are supported.
  - Ordinary profile credentials require an unlocked device. Separate hmac
    credentials follow the policy described in the [hmac guide](docs/hmac-luks.md).
  - Credentials are flash-persistent (up to 64) in a CRC-checked A/B format,
    written defer-ably from the main loop.
  - The CTAP2 client PIN is **independent** of the unlock passphrase. During
    `ssh-keygen -K`, OpenSSH still requires non-empty input when no CTAP2 PIN
    is configured; Fjaeger accepts that placeholder without persisting it.
    Once a PIN is configured, it is verified normally. The passphrase and
    CTAP2 PIN have separate persistent retry/block counters.
  - **User presence:** `PRESENCE auto` treats an unlocked device as present.
    `PRESENCE button` requires a fresh BOOT press for the FIDO operations
    listed above. The cyan LED pulse after signing is feedback.
- The MSC drive is a **12 MiB persistent FAT16 partition** in on-board flash,
  encrypted on the fly with AES-XTS using a **dedicated disk key** (independent
  of profiles). Metadata (boot, FAT, root) is initialized once on first boot;
  the data region is written lazily. Data survives reboot.
  - **Deferred write-behind:** USB MSC callbacks queue sector writes; the
    actual flash erase/program happens in the main loop (`fj_msc_task`), never
    inside a USB transaction. Data flushes continuously and before unmount.
    If a flush fails during `LOCK`, the USB volume closes immediately while
    the firmware retains the disk key and queued writes in RAM for retries.
    `STATUS`/`DISK STATUS` reports `disk_flush_pending`; keep the device powered
    until it clears. If the error is permanent, `DISK LOCK FORCE YES` discards
    the queued writes and wipes the RAM key. A power loss can still lose
    writes that the host already sent.
  - **Corruption detection:** a persistent CRC-32 table (one per 4 KiB block,
    stored in cleartext in the last blocks of the partition) is checked when
    blocks are read, so corrupted blocks are detected rather than served to the
    host. On a mount-time metadata corruption the drive fails closed (it is not
    auto-reformatted); the user must explicitly reset the drive. CRC-32 is
    corruption detection only — it is not cryptographic authentication.
  - Writing large files is slow and wears flash, because every sector update
    requires a flash erase.

## Hardware security status

Secure Boot, a signed update path and a hardware-protected hmac root are not
implemented or enabled. Current development hmac roots reside in ordinary flash.
Flash CRCs detect accidental corruption; they do not authenticate data or
prevent rollback. Treat the hardware as a development platform and keep
independent recovery access to anything protected by it.

## Acknowledgements

This project builds on the **Raspberry Pi Pico SDK** (Apache-2.0), which
bundles **TinyUSB** (MIT) and **mbedTLS** (Apache-2.0). Fjaeger's own source is
MIT-licensed; see [LICENSE](LICENSE).

## License

[MIT](LICENSE). Copyright (c) 2026 Espen Grøndahl.
