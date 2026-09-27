# Fjaeger — status and handover

Updated: 2026-09-27 (resident/discoverable credentials, CTAP2 PIN and
credential management)

## Short status

Fjaeger runs as a composite USB device on a **TENSTAR RP2350-USB with 16 MB
flash**:

- USB CDC console for PIN, locking and profiles.
- CTAP2/FIDO2 over HID for OpenSSH `sk-ecdsa`, including **resident keys**.
- Encrypted MSC prototype, available only while the device is unlocked.
- Addressable RGB status LED on GPIO22.

CTAP2 now supports resident/discoverable credentials end to end:
`authenticatorClientPIN` (0x06, PIN/UV auth protocol 1) and
`authenticatorCredentialManagement` (0x0A). Verified physically on the dongle
with OpenSSH: `ssh-keygen -t ecdsa-sk -O resident`, `ssh-keygen -K` (download),
signing and verification. The CTAP2 client PIN reuses the device's global PIN;
a dongle with no PIN set accepts any CTAP2 PIN (dummy mode), while a set PIN is
verified.

The dongle was left **locked** after the last test. Test PIN is **`12345`**.
This is only a development setup and must be changed before real use.

## Build environment

| Component | Value |
|---|---|
| Pico SDK | 2.2.0 (`/home/espegro/programming/pico-sdk`) |
| Board | `waveshare_rp2350_plus_16mb` |
| Toolchain | ARM-none-EABI GCC 14.2.1 |
| mbedTLS | 3.x from the Pico SDK |
| USB | TinyUSB from Pico SDK 2.2.0 |
| Flash | 16 MB |
| Flash tool | **picotool** (for `load`/`erase`/`reboot`) |

Prerequisites to build and flash: CMake ≥ 3.13, ARM-none-EABI toolchain,
**Pico SDK ≥ 2.1.0** (preferably 2.2.0) and **`picotool`** on PATH (for
flashing). The host tests need `cc` (x86-64); `pyserial` is optional for console
automation.

`waveshare_rp2350_plus_16mb` is used because it is electrically compatible with
the TENSTAR board. Pico SDK 2.0.0 with `pico2` previously produced no working
USB enumeration.

Build:

```bash
cmake -S . -B build \
  -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

The UF2 file is `build/fjaeger.uf2`. Put the dongle into BOOTSEL mode and run:

```bash
scripts/reflash.sh            # firmware only; drive + store (profiles/PIN) kept
scripts/reflash_wipe.sh       # erase all flash (firmware + drive + store), then flash
```

`reflash.sh` writes only the firmware and preserves the MSC drive and the store
(profiles, PIN, PUK, CTAP2 credentials). `reflash_wipe.sh` erases the whole
16 MB flash first (factory reset at the flash level) and asks for confirmation
(`YES`); on the next boot an empty "Default" profile is created. The console
command `RESET BOOTSEL` reboots into the USB bootloader programmatically.

### Do you lose your keys when re-flashing the firmware?

**No — not with a normal firmware flash.** `scripts/reflash.sh` preserves the
flash store, so your keys survive. You lose keys only on `reflash_wipe.sh`, on a
`STORE_VERSION` bump in the firmware source (development data is discarded
without migration), or on a console factory wipe (five wrong PUK attempts).

## Host tests

Each host test compiles the firmware source with `cc` against fake crypto/state
stubs, so it runs on x86-64 without hardware.

The CTAP2 test:

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Isrc/core -Isrc/fido -Isrc/led \
  tests/test_ctap2.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c \
  -o /tmp/fjaeger-test-ctap2
/tmp/fjaeger-test-ctap2
```

Expected: `ctap2 host tests: ok`.

The security-state test:

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led \
  tests/test_security.c src/core/state.c \
  -o /tmp/fjaeger-test-security
/tmp/fjaeger-test-security
```

Expected: `security host tests: ok`. It covers PIN lockout, PUK recovery, a full
live factory wipe and that auto-lock also closes the drive.

The profile test:

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Isrc/core -Isrc/fido -Isrc/led \
  tests/test_profile.c src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c \
  -o /tmp/fjaeger-test-profile
/tmp/fjaeger-test-profile
```

Expected: `profile host tests: ok`. It covers that `makeCredential` binds the
credential to the active profile and that `getAssertion` (with and without an
allowList) only resolves credentials in the active profile — a credential from
another profile is never used, including on duplicate registration via
excludeList.

The cache/persistence test (profile deletion + deferred flush):

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb -Isrc/led \
  tests/test_profile_erase.c src/core/state.c \
  src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c \
  -o /tmp/fjaeger-test-profile-erase
/tmp/fjaeger-test-profile-erase
```

Expected: `profile erase/flush host test: ok`. It covers that
`fj_state_profile_erase` clears both the live CTAP2 cache and the persistent
store as one consistent operation, and that a subsequent deferred
`fj_ctap2_task()` flush **does not** write deleted credentials back to flash.
Credentials in other profiles survive.

## Profiles (implemented 2026-09-27)

The old key slots were replaced by named profiles.

- A profile is **metadata and an access filter**, not a shared private key.
  Each CTAP2 credential keeps its own random P-256 key, credential ID and RP
  binding, and now has a `profile_id` tying it to one profile.
- Up to **8 profiles** (ID 0–7), each with a name. On an empty store, profile 0
  "Default" is created and selected automatically.
- **The selected profile is persisted** in flash and survives reboot. On boot a
  stored-but-invalid selection falls back to the first valid profile.
- `PROFILE LIST` / `CREATE` / `SELECT` / `RENAME` / `ERASE` replace
  `KEY LIST` / `SELECT` / `PROVISION` / `ERASE`.
- `makeCredential` binds new credentials to the active profile. `getAssertion`
  with or without an allowList accepts only credentials in the active profile.
  Wrong profile, wrong RP and unknown credential ID return no signature.
- `excludeList` checks duplicate registration **across profiles** (same
  credential ID) and rejects it without revealing which profile owns it.
- **Deleting the active profile is refused**, so at least one profile always
  exists and the active profile stays valid. Deleting an inactive profile
  removes the profile **and** all its credentials in one consistent operation:
  the live CTAP2 cache is cleared first, then the persistent store is updated —
  a deferred flush cannot write deleted credentials back to flash.
- The device PIN, recovery PUK and MSC drive are shared and independent of the
  profile selection; profile switching and deletion do not change the disk PIN,
  disk key or drive data.
- The flash format version was bumped (the old slot keys were removed).
  Development data may be lost; existing credentials must be re-enrolled.
- A factory wipe still clears both flash copies and all live key material,
  including profiles and credentials; on the next boot "Default" is re-created.

## Resident keys / CTAP2 PIN / credential management (implemented 2026-09-27)

- **`authenticatorClientPIN` (0x06)** implements PIN/UV auth protocol 1 over
  the HID channel: `getKeyAgreement`, `getPINRetries` and `getPinToken`, using
  P-256 ECDH, SHA-256 key derivation, AES-256-CBC and HMAC-SHA256. The CTAP2
  PIN reuses the device's single global PIN hash. If no PIN is configured the
  authenticator accepts any submitted PIN (dummy mode) so resident-key download
  works on a fresh device; if a PIN is configured it is verified.
- **`authenticatorCredentialManagement` (0x0A)** implements
  `getCredsMetadata`, `enumerateRPsBegin/GetNextRP` and
  `enumerateCredentialsBegin/GetNextCredential`, restricted to resident
  credentials in the **active profile**.
- **`authenticatorGetNextAssertion` (0x08)** continues resident-credential
  discovery (`numberOfCredentials`) within the active profile.
- `authenticatorGetInfo` advertises `rk`, `credMgmt`, `clientPin`,
  `pinUvAuthProtocols` and the `credProtect` extension (accepted but not
  enforced). `pinUvAuthToken` is deliberately **not** advertised, which makes
  libfido2 use the CTAP2.0 `getPinToken` flow.
- Verified physically with OpenSSH on the RP2350 dongle:
  - `ssh-keygen -t ecdsa-sk -O resident` enrolls a resident key.
  - `ssh-keygen -K` downloads the resident key (RP and credential enumeration
    both work; the downloaded key has the identical fingerprint).
  - `ssh-keygen -Y sign` + `-Y verify` succeed against the downloaded key.

> Note: CTAP2 requires canonical CBOR key ordering (string keys sorted by
> length, then bytewise). In `authenticatorGetInfo` options, `credMgmt` (length
> 8) must precede `clientPin` (length 9), and `getAssertion` key 0x04 is the
> user entity **map** `{"id": ...}`, not a raw byte string. libfido2 enforces
> these; violations made it fall back to U2F or fail to parse the response.

## Physically verified 2026-09-27 (profiles)

The profile feature is tested on the real RP2350 dongle with `ssh-keygen`
(`-Y sign`/`-Y verify`), which uses the same CTAP2 `getAssertion` path as SSH
login, as well as real SSH login against a local `sshd`:

- **Profile 0 "Default" is created automatically** on an empty store and
  selected; the device starts locked with a 900 s timeout.
- **PIN/PUK are set and work**; the device unlocks with the PIN.
- **Enrollment binds the credential to the active profile.** `PROFILE LIST`
  shows the correct credential count per profile.
- **Profile isolation with signing:** keyA in profile 1 signs when profile 1 is
  selected, is rejected (`invalid format`, RC 255) when profile 0 is selected,
  and works again after switching back to profile 1. Without an allowList
  (rp-hash search) filtering also applies.
- **Profile isolation with real SSH login (two-way):** `ssh` login with keyA
  succeeds in profile 1 (`SSH_LOGIN_OK`), is rejected in profile 0
  (`sign_and_send_pubkey: signing failed ... invalid format` →
  `Permission denied (publickey)`), and succeeds again after switching back to
  profile 1.
- **Selection, name and credential binding survive a watchdog `RESET`**; the
  active profile is restored correctly.
- **Deleting an inactive profile** makes its credentials unusable immediately
  and after reboot; other profiles still work. **Deleting the active profile**
  and an unknown profile are refused.
- **A locked device** refuses signing.
- **Factory wipe** after five wrong PUK attempts clears profiles and
  credentials; on the next boot the "Default" profile is re-created.

> Note: real SSH login requires a root-run `sshd` (a non-root `sshd` drops
> connections due to missing privilege separation). SSH `ControlMaster`/
> multiplexing in `~/.ssh/config` can mask isolation by reusing an existing
> connection without re-authenticating; use `-o ControlPath=none` when testing.

## Fixed in this round

### Basic firmware and USB

- Fixed USB enumeration by using the correct SDK and board profile.
- Fixed TinyUSB MCU config, device class and colliding endpoints.
- Removed console output before `tud_init()`, which previously crashed at boot.
- Adapted mbedTLS 3.x to the RP2350 and removed unused TLS/X.509 modules.
- Removed old X.509 attestation; CTAP2 uses `fmt: none`.

### Console, locking and flash

- Fixed tokenization of commands with arguments.
- Fixed PIN and slot storage to a CRC-checked A/B store in the last two flash
  sectors.
- Flash programming aligned to 256-byte pages.
- PIN, slots and CTAP2 credentials survive reset and a normal firmware flash.
- Auto-lock also unmounts MSC access.
- Auto-lock defaults to 900 seconds. `TIMEOUT <seconds>` is stored in the A/B
  flash store and survives reboot; `TIMEOUT 0` disables it persistently.
- Device PIN and disk PIN lock separately after five wrong attempts. The
  recovery PUK clears the lock; five wrong PUK attempts lock everything, reset
  live key material and erase both copies of the flash store.
- `DISK UNBLOCK <puk>` only clears the disk-PIN lock. The PUK cannot replace the
  disk PIN or decrypt the disk key.
- The console does not echo secrets and clears its command buffer after
  handling. Local echo/logging must be disabled in the terminal program.

### FIDO/CTAP2 and OpenSSH

- Fixed CTAPHID INIT, command values, multi-packet responses and transport
  buffer lifetimes.
- Fixed extended-APDU length and added a minimal CTAP1 REGISTER probe that
  libfido2/OpenSSH can use for token selection. This is **not full U2F/CTAP1**.
- Fixed canonical CBOR ordering in `GetInfo` and `GetAssertion`.
- Fixed `makeCredential`, `getAssertion`, authData, DER signature and the
  correct signature input.
- Moved large CTAP/crypto buffers out of the stack and increased available
  stack.
- Fixed P-256 public-key computation by giving mbedTLS a blinding RNG.
- Fixed a hang during signing. It was isolated to deterministic ECDSA via
  HMAC-DRBG; the likely cause is the interaction with the Pico SDK's globally
  locked SHA-256 hardware context. Signing now uses the RP2350 hardware RNG for
  both the ephemeral scalar and blinding, and physical signing completes.
- Added explicit validation of a stored private P-256 key before signing.

### MSC and LED

- Repaired the FAT12 base image for the MSC prototype.
- MSC reports not-ready when the dongle is locked or auto-lock engages.
- Implemented a WS2812/SK6812-compatible LED driver via PIO on GPIO22:
  - red: locked
  - green: unlocked
  - yellow: not USB-enumerated
  - short blue pulse: console, FIDO or drive activity
  - brief security pulses: green flash on PIN unlock, red flash on lock, cyan
    flash when an SSH key signs

## Persistent encrypted MSC drive (implemented 2026-09-26)

The MSC drive was made a **12 MiB persistent flash partition** and decoupled
from the key slots.

- **Partition:** `0x10100000`–`0x10D00000` (12 MiB), at offset `0x00100000`
  from XIP. Firmware (~128 KB) lives before this; PIN/profiles/CTAP2/disk key
  live in the last 8 KiB. No overlap.
- **Filesystem:** FAT16, 512-byte sectors, 1 sector/cluster. Metadata (boot,
  both FATs, root directory) is initialized once on first boot; the data region
  is written lazily. Replaces the old 8 KiB RAM disk.
- **Encryption:** AES-128-XTS with a dedicated permanent disk key stored in the
  store, sector LBA as the tweak. The drive is **independent of key slots** —
  `KEY SELECT`, `KEY PROVISION` and `KEY ERASE` do not affect drive data.
- **Deferred write-behind:** USB MSC callbacks queue sector writes in a pending
  queue; the actual flash erase/program happens in `fj_msc_task()` (main loop),
  never inside a USB transaction. Data flushes on `LOCK`/unmount
  (`fj_msc_set_ready(false)`) and continuously in the main loop.
- **Integrity:** a persistent CRC-32 table (one per 4 KiB block, stored in
  cleartext in the last 4 blocks of the partition) is verified on mount.
  Corruption from power loss or tampering is detected, and the drive is
  re-initialized instead of serving corrupt data.
- **Independent drive lock:** `UNLOCK <pin>` only unlocks the **device** (keys);
  the encrypted drive is a separate step via `DISK UNLOCK`/`DISK LOCK`/
  `DISK STATUS`. `LOCK` and auto-relock also close the drive; `DISK UNLOCK`
  requires the device to be unlocked. When the drive is locked it is
  not-ready (NOT_READY).

Physically verified:
- The drive mounts as a ~12 MiB vfat volume when unlocked.
- Files written and read back correctly (1 MiB binary file + text file).
- **Data survives watchdog `RESET` and cold start**, over several
  write/reboot cycles (deferred write + CRC table update and verify correctly).
- Slot switch (slot 0 → 1) does **not** change drive data — the disk key is
  independent.
- **Independent state:** `UNLOCK` gives `state: unlocked` while `disk: locked`
  (drive not mounted); `DISK UNLOCK` mounts it as a separate step; `DISK LOCK`
  unmounts the drive while the device stays unlocked; `LOCK` closes both device
  and drive; `DISK UNLOCK` with the device locked gives `ERR device locked`.
- **Integrity detection:** by erasing the boot block (0xFF) without updating
  the CRC table, the device detected the corruption and re-initialized the
  filesystem (existing files gone) — corrupt data is not served.
- During debugging an address bug was fixed: `DISK_FLASH_START` must be an XIP
  offset, not an absolute address (the error gave a hard fault on
  `0x20100000`).
- A CRC-table bug was fixed: magic/header collided with `CRC[0]` and gave a
  false mismatch on mount (data "disappeared" on reboot). Fixed by reserving a
  header offset (`CRC_HEADER_SIZE`) that does not overlap the CRCs.

Known trade-off: every write to a new flash block requires erasing a 4 KiB
block, so large files write slowly and wear flash. The filesystem is FAT16 (max
~2 GB with a suitable cluster size), but the partition is 12 MiB. There is no
wear leveling; the most-written sectors (FAT, root directory) wear faster.

## What should be tested next

Prioritized list for the next development session (completed and verified items
are removed):

1. **Physical multi-profile regression.** On the dongle: create profiles, enroll
   `ecdsa-sk` credentials in at least two profiles, and verify that only the
   credentials in the selected profile sign; that profile selection, name and
   binding survive reset/cold start; that deleting an inactive profile makes its
   credentials unusable immediately and after reboot; and that profile deletion
   does not affect drive data.
2. **More FIDO clients / OS.** Try browser/WebAuthn and ideally both Linux and
   Windows/macOS. Also test several FIDO devices connected at once.
3. **Interrupts and malformed traffic.** Test CTAPHID CANCEL, channel lock,
   fragmented and maximum-size messages, wrong sequence numbers and USB
   disconnect mid-response.
4. **Long-run test.** Run many signing, lock/unlock cycles and auto-lock while
   HID and MSC are used simultaneously. Look for USB resets, heap/stack issues
   and flash wear.
5. **MSC data integrity.** Write and read files over many lock/unlock cycles,
   auto-lock during I/O and active-profile switches. The drive is now a
   persistent flash partition (12 MiB) with a dedicated disk key; verify that
   contents never leak in cleartext while locked and that data survives reboot.
6. **LED regression.** Visually confirm red/green/yellow and that the blue
   activity pulse does not obscure the lock status for too long, especially
   under continuous drive or HID I/O.
7. **Real login on an external host.** This session used a local `sshd`; also
   verify against a remote/service host.

## Known limitations and security work

- The PIN and PUK are sent as command text over CDC. The firmware does not echo
  input and clears its command buffer after use, but the user must disable local
  echo and any logging in the terminal program.
- The device PIN, disk PIN and PUK are now derived with salted
  PBKDF2-HMAC-SHA256 (a fresh random salt per field), so a dumped flash store
  cannot be brute-forced offline with a fast hash. The disk key is wrapped with
  the PBKDF2-derived disk-PIN key. The CTAP2 client-PIN verifier is
  `LEFT(SHA-256(pin),16)` because the CTAP2 PIN protocol only transmits that
  value. PBKDF2 runs in the main loop and takes a couple of seconds on the
  RP2350; a time delay in addition to the persistent attempt counters is still
  missing. The SSH/CTAP2 credential private keys themselves are stored in flash
  in clear, so a physical flash dump reveals them regardless of the PIN.
- There is no dedicated physical touch button. CTAP `up` in practice represents
  that the device is already unlocked via the PIN, not a fresh physical
  confirmation per use.
- Full U2F/CTAP1 is not implemented. Only the compatibility probe that
  OpenSSH/libfido2 needs for token selection exists.
- Only ES256 / P-256 is supported. `ed25519-sk` is not supported.
- The CTAP2 implementation is a necessary subset, not a certified complete FIDO2
  authenticator. In particular `authenticatorReset` is missing.
- The signature counter is zero because a volatile counter would move backwards
  after reboot. A persistent monotonic counter is not implemented.
- MSC is now a **12 MiB persistent FAT16 partition** in on-board flash,
  encrypted on the fly with AES-XTS using a **dedicated disk key** (independent
  of profiles). Filesystem metadata is initialized once; the data region is
  written lazily. Writing large files is slow and wears flash (every sector
  update requires erasing a 4 KiB block). Flash layout: firmware ~128 KB from
  `0x10000000`, 12 MiB drive partition from `0x10100000` (offset `0x00100000`),
  store in the last 8 KiB.
- AES-XTS provides confidentiality, but not authentication or integrity
  protection.
- Keys live in ordinary external flash; secure boot, signed firmware, flash
  protection and resistance to physical extraction are not finished.
- The flash store uses A/B and CRC, but needs dedicated tests for power loss
  exactly during erase/program and for generation-counter wrap.

## Recommended next order

1. Test points 1–4 above are run and the results documented. Continue with the
   remaining items in "What should be tested next".
2. Add automated parser and transport tests for CTAPHID/CBOR.
3. **PIN/PUK/disk-PIN bruker nå saltet PBKDF2-HMAC-SHA256** (per-felt tilfeldig
   salt). Gjenstår: en tidsforsinkelse i tillegg til de vedvarende
   forsøkstellerne, og vurder om RP2350 kan bære flere iterasjoner eller en
   minnehard KDF.
4. Decide whether the project should have a physical confirmation button for
   correct FIDO user-presence semantics.
5. **The persistent MSC partition is implemented** (12 MiB, dedicated disk key,
   XTS). Remaining: optimize write performance/wear (e.g. write coalescing and
   lower erase frequency), consider FAT32 if capacity grows, and consider
   per-sector integrity protection.
6. Plan secure boot, signed updates and key protection before use with real
   secrets.

## Relevant commits

```text
3c2ad51  Local baseline
70f0fef  Document physical console and persistence tests
5f1ac23  Fix CTAP2 OpenSSH enrollment and signing
```