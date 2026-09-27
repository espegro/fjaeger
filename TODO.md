# TODO: Profiles, SSH/FIDO credentials and storage hardening

## Goal

Turn the original console slots into named profiles such as "Private", "Work"
and "Administration". Each profile has several independent SSH/FIDO
credentials. Only the credentials in the selected profile can be used or
discovered. Enrollment automatically binds new credentials to the selected
profile.

> **Status:** profiles, resident/discoverable credentials, CTAP2 PIN +
> credential management, PBKDF2 storage hardening and the LED security pulses
> are **implemented and physically verified**. This document is the working plan
> and record. Completed items are marked `[x]`; open items are `[ ]`.

## Current situation

- `PROFILE LIST / CREATE / SELECT / RENAME / ERASE` manage up to eight named
  profiles in `src/core/keys.c`. A profile is metadata plus an access filter.
- CTAP2 has a store of eight credentials. Each credential has its own random
  P-256 key, credential ID and RP binding, plus a `profile_id` tying it to one
  profile.
- CTAP2 uses the selected profile: only credentials in the active profile can be
  used or discovered, and new credentials are bound to the active profile.
- The encrypted MSC drive has a separate disk key and disk PIN.
- Auto-lock defaults to 900 seconds. `TIMEOUT` is stored persistently;
  `TIMEOUT 0` disables auto-lock. The device lock also closes the drive.

Relevant files: `src/core/keys.h/.c`, `src/core/state.h/.c`,
`src/core/crypto.h/.c`, `src/fido/ctap2.h/.c`, `src/fido/pin.h/.c`,
`src/led/rgb_led.h/.c` and `src/usb/cdc_console.c`.

## Model

1. Keep up to eight profiles, identified by ID 0–7 and a name.
2. A profile is metadata and an access filter. It does not generate a shared
   private key for all its credentials.
3. Each CTAP2 credential has a `profile_id`, but keeps its own randomly
   generated private key, credential ID and RP binding.
4. Keep eight credentials total for now, distributed freely among the profiles.
   Eight profiles does not mean eight credentials per profile. A larger
   capacity can be considered separately; the A/B record must still fit in one
   4 KiB sector.
5. On an empty store, profile 0 is created with the name "Default" and
   selected.
6. Store the selected profile permanently. On boot the stored profile must
   exist; otherwise a valid profile with a clearly defined fallback is chosen.
7. The device PIN and recovery PUK remain shared for the whole dongle.
8. The MSC drive remains shared and independent of the profile selection.
   Profile switching or deletion must not change the disk PIN, disk key or
   drive data.

Example:

| Profile | Credentials |
|---|---|
| 0: Private | Private server, GitHub |
| 1: Work | Work server, GitLab |
| 2: Administration | Ops server |

When profile 1 is selected, a signing request with a credential ID from
profile 0 is rejected. The SSH file on the PC still points at the same
credential ID; the user must select the right profile before it can be used.

Profiles provide organization and access control in the firmware. With a shared
PIN and free profile selection they are not separate security domains with their
own users.

## Console commands

Use clear `PROFILE` commands as the main interface:

| Command | Behavior |
|---|---|
| `PROFILE LIST` | Show ID, name, active marker and credential count |
| `PROFILE CREATE <id> <name>` | Create an empty profile; reject an existing ID |
| `PROFILE SELECT <id>` | Select and persist the active profile; reject an unknown ID |
| `PROFILE RENAME <id> <name>` | Rename without changing credentials |
| `PROFILE ERASE <id>` | Delete the profile and all its credentials |

- Mutating commands require an unlocked device, like the old `KEY` commands.
- `STATUS` shows the active profile and the relevant credential count.
- Refuse deleting the active profile; the user must select another first. This
  means at least one profile always exists and the active profile stays valid.
- Do not let `CREATE` or `RENAME` overwrite a profile or its credentials.
- Define and document limits for names and IDs. Simple names without spaces are
  sufficient in the first version.
- The old `KEY` commands are gone (a misleading `KEY PROVISION` that generated
  keys CTAP2 never used would have been confusing).
- `RESET BOOTSEL` reboots into the ROM USB bootloader for re-flashing (not
  listed in HELP).

## CTAP2 changes

- [x] `makeCredential` binds the credential to the active profile.
- [x] `getAssertion` with an `allowList` accepts only credentials in the active
      profile.
- [x] Credential ID and RP hash are both validated before signing.
- [x] A search without an `allowList` also filters on the active profile.
- [x] `excludeList` is handled correctly. Existing ID/RP bindings are checked
      across profiles and duplicate registration is rejected without revealing
      profile names.
- [x] Profile switching/deletion invalidates any in-progress assertion
      enumeration and other buffered credential selection.
- [x] A locked device still rejects enrollment and signing.

ECDSA P-256 / ES256 is kept in the first version. Ed25519 is not part of this
task.

## Storage and deletion

- [x] The old slot keys were replaced with profile metadata; unused
      private/AES key material is not retained.
- [x] The credential format was extended with a profile ID and the active
      profile is stored.
- [x] The flash format version was bumped. Development data may be lost;
      migration is not required. Document that existing credentials must be
      re-enrolled.
- [x] The A/B format, generation counter, CRC and the 4 KiB size check are kept.
- [x] Profile deletion updates both the persistent store and the CTAP2 cache in
      one consistent operation. A stale cache cannot write deleted credentials
      back to flash via a deferred flush.
- [x] Document that ordinary A/B deletion can leave key material in the older
      flash copy until it is overwritten. Do not claim physical secure deletion
      of individual profiles without implementing and testing it.
- [x] Factory wipe still deletes both flash copies and all live key material,
      including profile and credential state.

## Resident credentials (implemented and verified)

Profiles were designed so that resident/discoverable credentials can be used
within the active profile. This required more than advertising `rk: true`:

- [x] Store the resident marker, RP information and user ID/metadata correctly.
- [x] Implement the correct user entity in the assertion response.
- [x] Handle multiple matches with `numberOfCredentials` and
      `getNextAssertion`.
- [x] Implement the credential-management and PIN/UV-authentication functions
      so OpenSSH/libfido2 can actually download keys with `ssh-keygen -K`.
- [x] Discovery and export of credential handles only shows the active profile.
- [x] Test `ssh-keygen -t ecdsa-sk -O resident` and `ssh-keygen -K` end to end.

Implemented and physically verified on the RP2350 dongle:
`authenticatorClientPIN` (0x06, PIN/UV auth protocol 1 with ECDH/HKDF/AES-CBC/
HMAC), `authenticatorCredentialManagement` (0x0A) and
`authenticatorGetNextAssertion` (0x08). `ssh-keygen -t ecdsa-sk -O resident`,
`ssh-keygen -K`, signing and verification work end to end with profile
isolation (active profile only). The CTAP2 PIN reuses the device's global PIN:
no PIN set → accepts anything (dummy); PIN set → verified against the stored
verifier. Note: CTAP2 requires canonical CBOR key ordering (ascending length) —
`credMgmt` must precede `clientPin` in the getInfo options.

A search by RP hash alone is not full resident support. Private keys are never
exported; what can be fetched to the PC is the credential handle and public
key.

## Storage hardening: slow salted KDF (implemented and verified)

The device PIN, disk PIN and recovery PUK are no longer stored with fast
SHA-256 / HKDF hashes that could be brute-forced offline from a flash dump.

- [x] Added `fj_pbkdf2_sha256()` (PBKDF2-HMAC-SHA256) to `crypto.c`, validated
      against RFC 6070 test vectors.
- [x] Device PIN: stored as a salted PBKDF2 hash + a separate
      `LEFT(SHA-256(pin),16)` CTAP2 client-PIN verifier (the CTAP2 protocol only
      transmits that value). Verified in constant time.
- [x] Disk PIN: the disk key is wrapped with the PBKDF2-derived disk-PIN key;
      the stored verification hash is the same PBKDF2 output.
- [x] Recovery PUK: stored as a salted PBKDF2 hash.
- [x] Per-field random salt (16 bytes) persisted in the store; store version
      bumped.
- [x] Wrong-PIN / wrong-PUK / wrong-disk-PIN counters are reset on success and
      block after `FJ_MAX_*_FAILS`; five wrong PUKs trigger a factory wipe.
- [x] Physically verified: PIN unlock/lockout/PUK-recovery, disk set/unlock/
      mount/read-write, locked-disk inaccessible to the host, and reboot
      persistence of PIN/PUK/disk key.

Open items:
- [ ] Add a time delay on failed attempts in addition to the persistent
      counters.
- [ ] Consider whether the RP2350 can afford more PBKDF2 iterations or a
      memory-hard KDF (PBKDF2 at 100k runs in the main loop and takes a couple
      of seconds).
- [ ] The SSH/CTAP2 credential private keys are stored in flash in clear; only
      the disk key is wrapped. Protecting them (e.g. wrapping all key material)
      is a larger security change.

## LED security pulses (implemented)

The RGB status LED now shows distinct brief pulses for security events in
addition to the steady lock/USB state:

- [x] Green flash on a successful PIN unlock.
- [x] Red flash on lock.
- [x] Cyan flash when an SSH key signs (after a successful ECDSA signature).
- [x] Steady states unchanged: green = unlocked, red blink = locked,
      amber = not enumerated, blue = USB activity / suspended.
- [ ] Visually confirm the cyan blink on the dongle during an SSH signing
      (the signing path that calls `fj_led_sign()` is verified to run, but the
      physical blink needs a human observer).

## Acceptance tests

- [x] An empty device starts locked with profile 0 "Default" and a 900-second
      timeout.
- [x] Create profile A and B, enroll at least two credentials in A and one in B.
- [x] All A credentials sign when A is selected; the B credential is rejected.
- [x] After switching to B the result is reversed.
- [x] Wrong profile, wrong RP and unknown credential ID return no signature.
- [x] Profile selection, name and credential binding survive reset and cold
      start.
- [x] Deleting an inactive profile makes its credentials unusable immediately
      and after reboot. Other profiles still work.
- [x] Deleting the active profile and overwriting via `CREATE` are rejected.
- [x] A full credential store is rejected without changing existing
      credentials.
- [x] Lock/auto-lock rejects signing and closes the MSC regardless of the
      selected profile.
- [x] Profile switching and deletion do not affect drive data.
- [x] Factory wipe after five wrong PUK attempts clears all profiles and
      credentials; on the next boot an empty "Default" profile is created.
- [x] Existing host tests and firmware builds pass. Host tests were added that
      specifically cover the profile filter and cache/persistence interplay.
- [ ] Physical OpenSSH regression: enroll, sign, verify and real SSH login with
      credentials from at least two profiles (enroll/sign/verify with one
      profile and `ssh-keygen -K` are verified; two profiles and real SSH login
      remain).
- [ ] Real SSH login against an external (non-local) host.

## Implementation order

1. Model and persistent profile metadata, including an empty Default profile.
2. Profile commands and validation in the console.
3. Profile binding on enrollment and filtering of all credential lookups.
4. Consistent profile deletion and live CTAP2 cache handling.
5. Host tests, firmware builds and physical OpenSSH regression.
6. Update README.md and STATUS.md with the actually tested behavior.
7. Resident credentials as a separate extension (now implemented and verified).
8. PBKDF2 storage hardening for PIN/PUK/disk key (now implemented and verified).
9. LED security pulses (now implemented).