# Fjaeger Security Findings

Repository: `espegro/fjaeger`  
Reviewed branch: `main`  
Reviewed commit: `5d57aa6`  
Date: 2026-09-27

## Purpose

This document records security findings identified during a review of the Fjaeger firmware.

Fjaeger is an RP2350-based USB security key combining:

- CTAP2/FIDO2 authentication for OpenSSH `sk-ecdsa`
- Resident/discoverable credentials
- Profile-based credential isolation
- An encrypted USB Mass Storage device
- Device PIN, disk PIN, and recovery PUK handling
- Encrypted backup and restore
- Persistent flash-backed state

The overall structure is good, and the code already contains several solid security design choices, including:

- A/B flash storage with generation counters and CRC
- Hardware RNG through the Pico SDK
- AES-GCM protection of persisted CTAP2 private keys
- Explicit wiping of sensitive RAM buffers in several code paths
- Persistent retry counters
- Separate device, disk, and recovery secrets
- Explicit acknowledgement that the RP2350 is not a secure element
- Physical testing of OpenSSH enrollment, signing, resident-key recovery, PUK recovery, and backup/restore

However, several issues should be addressed before treating the firmware as suitable for protecting real secrets against an attacker capable of reading device flash.

---

# Summary

| Severity | Finding |
|---|---|
| Critical | Disk encryption key can be reconstructed directly from the persisted flash store |
| High | CTAP2 PIN verifier permits fast offline brute-force of the device PIN |
| High | Disk integrity protection does not match the security claim in the README |
| High | Filesystem integrity failure can cause destructive automatic reinitialization |
| Medium/High | PIN changes and restore operations are not transactional |
| Medium | Credential metadata is not authenticated by AES-GCM |
| Medium | Some secret comparisons use `memcmp()` instead of constant-time comparison |
| Medium | PIN token and credential-management session state should be explicitly invalidated on device lock |
| Low/Medium | Security-critical parsers should be fuzz-tested and continuously tested under sanitizers |

---

# FJ-001: Disk key can be reconstructed directly from flash

Severity: **Critical**

Affected area:

- `src/usb/msc_disk.c`
- `src/core/keys.c`

## Description

The disk PIN currently derives a wrapping key:

```c
wrap = PBKDF2(pin, salt)
```

The disk key is wrapped using XOR:

```c
enc = disk_key XOR wrap
```

However, the same `wrap` value is also stored as the disk PIN verification hash:

```c
hash = wrap
```

The persistent store therefore contains both:

```text
disk_secret_enc = disk_key XOR PBKDF2(pin)
disk_pin_hash   =              PBKDF2(pin)
```

An attacker who can dump the flash does not need to recover the PIN.

They can directly compute:

```text
disk_key = disk_secret_enc XOR disk_pin_hash
```

This completely bypasses the intended protection provided by the disk PIN.

## Impact

A full flash dump reveals the AES-XTS disk key immediately.

The encrypted 12 MiB storage partition can then be decrypted without:

- guessing the disk PIN
- running PBKDF2
- triggering retry limits
- knowing the PUK

This conflicts with the current security model described in the README.

## Recommended fix

Do not persist a value that is identical to the key used to wrap the disk key.

Use authenticated key wrapping instead.

Recommended construction:

```text
K = PBKDF2-HMAC-SHA256(
        disk_pin,
        salt,
        iterations
    )
```

Then protect the random disk key with AES-256-GCM:

```text
ciphertext, tag =
    AES-256-GCM(
        key = K,
        nonce = random_nonce,
        plaintext = disk_key,
        aad = "Fjaeger disk key v1"
    )
```

Persist only:

```text
salt
nonce
ciphertext
tag
```

Do not persist a separate `disk_pin_hash`.

On unlock:

1. Derive `K` from the supplied PIN.
2. Attempt AES-GCM decryption.
3. A valid authentication tag means the PIN is correct.
4. An invalid tag means the PIN is wrong.

This preserves slow offline resistance because every PIN guess requires PBKDF2.

## Suggested store fields

Replace:

```c
uint8_t disk_secret_enc[32];
uint8_t disk_pin_salt[16];
uint8_t disk_pin_hash[32];
```

with something similar to:

```c
uint8_t disk_secret_enc[32];
uint8_t disk_pin_salt[16];
uint8_t disk_wrap_nonce[12];
uint8_t disk_wrap_tag[16];
```

The exact layout can be changed as part of a `STORE_VERSION` migration.

---

# FJ-002: CTAP2 PIN verifier permits fast offline brute-force

Severity: **High**

Affected area:

- `src/core/state.c`
- `src/core/keys.c`
- `src/fido/pin.c`

## Description

The console/device PIN is protected using:

```text
PBKDF2-HMAC-SHA256(pin, salt, 100000)
```

This is appropriate for protecting the PIN against offline guessing.

However, the firmware also persists:

```text
LEFT(SHA-256(pin), 16)
```

as:

```c
pin_ctap2_verifier
```

This value is required by the CTAP2 PIN protocol implementation.

Because it is stored directly in flash, an attacker with a flash dump can test PIN guesses using only SHA-256:

```python
if sha256(candidate_pin)[:16] == verifier:
    # PIN recovered
```

The attacker does not need to run PBKDF2 for each guess.

## Impact

The security of the device PIN against a flash attacker is reduced to:

- PIN entropy
- raw SHA-256 guessing speed

Once the PIN has been recovered, the attacker can derive the master-key wrapping value:

```text
PBKDF2(pin, m_salt_pin)
```

and recover the credential master key:

```text
M = m_enc_pin XOR PBKDF2(pin, m_salt_pin)
```

The attacker can then decrypt stored CTAP2 credential private keys.

The attack chain is:

```text
flash dump
    |
    v
pin_ctap2_verifier
    |
    v
fast SHA-256 brute force
    |
    v
device PIN
    |
    v
PBKDF2(PIN, m_salt_pin)
    |
    v
master key M
    |
    v
decrypt CTAP2 private keys
```

## Recommended fix

This is partly a consequence of CTAP2 PIN protocol design and the absence of hardware-protected secret storage.

Consider one of these designs.

### Option A: Separate unlock passphrase from CTAP2 PIN

Use two different secrets:

```text
Device unlock passphrase
    -> protects master key M

CTAP2 PIN
    -> CTAP2 PIN/token protocol only
```

The device unlock passphrase may be significantly longer than a normal FIDO PIN.

Compromise of the CTAP2 verifier would then not automatically reveal the secret that unwraps `M`.

This is probably the simplest strong design for an RP2350 prototype.

### Option B: Hardware-bound protection

Protect the CTAP2 verifier using a device-bound secret stored or derived from RP2350 OTP/fuse-protected material.

This becomes more meaningful together with:

- Secure Boot
- `BOOT_CPROT`
- boot-ROM restrictions
- signed firmware updates

Do not claim strong physical protection unless the relevant hardware protections are actually enabled.

---

# FJ-003: Disk integrity protection is incomplete

Severity: **High**

Affected area:

- `src/usb/msc_disk.c`
- `README.md`

## Description

The implementation maintains a CRC-32 value for each 4 KiB encrypted disk block.

The README describes this as integrity protection and states that corruption is verified on mount.

However, the mount logic appears to do:

```c
if (!crc_table_load()) {
    init_filesystem();
} else if (!boot_sector_valid()) {
    init_filesystem();
}
```

`boot_sector_valid()` verifies only block 0 against:

```c
block_crcs[0]
```

Normal reads through `read_block_apply()` decrypt blocks but do not appear to validate every block against:

```c
block_crcs[idx]
```

Therefore most data blocks are not actually checked against their CRC when read.

## Impact

Corruption in ordinary filesystem/data blocks may be returned to the host without detection.

The README currently implies stronger coverage than the implementation provides.

## Additional cryptographic limitation

CRC-32 is not cryptographic authentication.

An attacker capable of modifying flash can replace both:

```text
ciphertext block
matching CRC
```

with another valid pair.

Likewise, an old full-disk snapshot and matching CRC table can be rolled back.

AES-XTS provides confidentiality but no cryptographic authentication.

## Recommended fix

Decide which security property is intended.

### If the goal is accidental-corruption detection

Validate each block CRC before returning decrypted data.

For example:

```c
if (crc32_block(clear) != block_crcs[idx]) {
    return false;
}
```

Then document CRC correctly as corruption detection, not tamper protection.

### If the goal is cryptographic integrity

Use a keyed MAC or authenticated storage design.

Examples:

```text
HMAC-SHA256(integrity_key, block_number || ciphertext)
```

or an authenticated encryption/storage construction designed for sectors.

AES-XTS alone should not be described as providing integrity.

---

# FJ-004: Integrity failure triggers destructive filesystem initialization

Severity: **High**

Affected area:

- `src/usb/msc_disk.c`

## Description

If the CRC table cannot be loaded, or the boot block fails validation, the firmware calls:

```c
init_filesystem();
```

This is destructive behavior triggered automatically by integrity or corruption failure.

A transient flash issue, interrupted CRC-table update, or isolated metadata corruption can therefore cause the firmware to start rewriting filesystem metadata.

## Impact

A recoverable corruption event can become permanent data loss.

For a security device, corruption handling should preferably be fail-closed and non-destructive.

## Recommended fix

On integrity failure:

```text
DISK ERROR
```

Do not automatically initialize or format the disk.

Require an explicit destructive administrative action, for example:

```text
DISK FORMAT
```

Potential recovery commands could also be provided:

```text
DISK CHECK
DISK RECOVER
```

Any destructive operation should be clearly separated from normal unlock/mount behavior.

---

# FJ-005: PIN and recovery state updates are not transactional

Severity: **Medium/High**

Affected area:

- `src/core/state.c`
- `src/core/keys.c`

## Description

A PIN change writes persistent state multiple times.

The current sequence is approximately:

```text
1. write new PIN hash/verifier
2. write new master-key wrap
```

For example:

```c
fj_keys_set_pin(...)
```

is followed later by:

```c
master_wrap_with(..., fj_keys_set_master_pin_wrap)
```

Each function causes a separate flash-store commit.

If power is lost between these writes, the store can contain:

```text
new PIN verifier/hash
old master-key wrap
```

The new PIN may authenticate successfully while failing to recover the master key.

Similar multi-stage update patterns exist in restore and PUK-related operations.

## Impact

Unexpected power loss during a security-state update can cause:

- credentials to become temporarily or permanently unavailable
- inconsistent PIN/master-wrap state
- recovery to depend on whether the PUK was already configured
- difficult-to-diagnose device state

## Recommended fix

Prepare the entire new persistent record in RAM first.

For example:

```text
derive new PIN state
derive new master-key PIN wrap
derive any new PUK state
update counters
update metadata

commit once
```

Then write one new A/B store generation.

The existing A/B architecture is already well suited for this.

Avoid security-sensitive operations that require two or more independently durable commits to represent one logical transaction.

---

# FJ-006: Credential metadata is not authenticated by AES-GCM

Severity: **Medium**

Affected area:

- `src/fido/ctap2.c`
- `src/core/keys.h`

## Description

Credential private keys are encrypted using AES-GCM:

```text
AES-GCM(M, nonce, private_key)
```

However, no Additional Authenticated Data (AAD) is used.

Only the private scalar is authenticated.

The following metadata is stored separately and is not covered by the GCM tag:

```text
credential_id
public_key
rp_id_hash
rp
user_id
profile_id
resident
in_use
```

## Impact

An attacker able to alter flash may be able to modify credential metadata without invalidating the encrypted private key.

Potentially interesting metadata manipulation includes:

- moving a credential between profiles
- changing RP binding metadata
- changing resident/discoverable flags
- altering stored public-key metadata
- changing credential identifiers

Some changes may fail elsewhere, but the cryptographic record itself does not bind the private key to its intended metadata.

This becomes particularly important if Secure Boot and flash access protections are later enabled.

## Recommended fix

Authenticate immutable security-relevant credential metadata as AES-GCM AAD.

For example:

```text
AAD =
    record_version ||
    credential_id ||
    profile_id ||
    rp_id_hash ||
    public_key ||
    resident
```

Then:

```text
AES-GCM(
    key = M,
    nonce = private_key_nonce,
    plaintext = private_key,
    aad = metadata
)
```

Any metadata modification will then cause decryption authentication to fail.

Be careful about including mutable fields in AAD unless re-encryption is performed when they change.

---

# FJ-007: Secret comparisons should use one constant-time helper

Severity: **Medium**

Affected area:

- `src/fido/pin.c`
- potentially other crypto-sensitive comparisons

## Description

Some sensitive comparisons are implemented correctly using an accumulator, for example in device PIN verification.

Other secret values are compared using `memcmp()`.

Examples include comparisons of:

```text
CTAP2 PIN verifier
pinUvAuth/HMAC values
```

Standard `memcmp()` is not guaranteed to run in constant time.

## Impact

This may introduce timing side channels when secrets are compared.

The practical exploitability over USB may be limited, but security-sensitive comparison behavior should be consistent.

## Recommended fix

Add one helper:

```c
bool fj_ct_equal(const void *a, const void *b, size_t n);
```

Example implementation:

```c
bool fj_ct_equal(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a;
    const uint8_t *y = b;
    uint8_t diff = 0;

    for (size_t i = 0; i < n; i++) {
        diff |= x[i] ^ y[i];
    }

    return diff == 0;
}
```

Use it consistently for:

- PIN verifiers
- HMAC values
- authentication tags where not already handled internally
- recovery-secret verification
- other authentication material

Comparisons of non-secret identifiers such as RP IDs or credential IDs do not necessarily require constant-time behavior.

---

# FJ-008: Explicitly invalidate CTAP2 PIN/session state on lock

Severity: **Medium**

Affected area:

- `src/core/state.c`
- `src/fido/pin.c`
- `src/fido/ctap2.c`

## Description

The implementation contains:

```c
fj_pin_reset_token()
```

and various stateful credential-management/discovery structures.

The device lock function currently focuses on:

- locking MSC
- LED state
- wiping master key M
- changing device state to locked

Security-sensitive CTAP2 token/session state should be explicitly invalidated whenever the device transitions to locked state.

## Impact

Even if current operation checks prevent direct signing while locked, stale authentication or enumeration state increases complexity and can create unexpected state reuse across lock boundaries.

A lock operation should represent a complete security-session boundary.

## Recommended fix

On every lock:

```text
wipe master key
wipe disk key
invalidate pinUvAuthToken
invalidate credential management cursors
invalidate resident credential discovery state
wipe transient crypto buffers where practical
```

For example, `fj_state_lock()` should call something equivalent to:

```c
fj_pin_reset_token();
fj_ctap2_invalidate_discovery();
```

and any credential-management enumeration state should also be cleared.

A successful new PIN verification should mint a fresh token.

---

# FJ-009: Add CI, sanitizers, and parser fuzzing

Severity: **Low/Medium**

Affected area:

- repository testing and CI

## Description

The repository already contains useful host-side tests:

```text
test_security.c
test_ctap2.c
test_profile.c
test_profile_erase.c
```

This is a strong foundation.

However, these tests are currently mostly state/functional tests, and several cryptographic operations are stubbed.

Security-sensitive parsers would benefit from fuzz testing.

Good targets include:

- CBOR decoder
- CTAPHID frame assembly
- CTAP2 request parsing
- ClientPIN parsing
- Credential-management parsing

## Recommended fix

Add GitHub Actions that run the host tests with strict compiler flags:

```text
-Wall
-Wextra
-Werror
```

Also run host tests under:

```text
-fsanitize=address
-fsanitize=undefined
```

Where practical, add libFuzzer or AFL++ targets for:

```text
src/fido/cbor.c
src/fido/u2f.c
src/fido/ctap2.c
src/fido/pin.c
```

Important fuzzing properties:

- no out-of-bounds reads
- no out-of-bounds writes
- no integer-wrap bugs
- no infinite loops
- malformed CBOR never escapes bounds
- arbitrary CTAPHID sequences cannot corrupt state
- profile boundaries cannot be bypassed
- malformed credential-management messages cannot expose cross-profile data

---

# Additional recommended tests

## Disk key wrapping test

Create a regression test that verifies the persisted disk-key record does not directly reveal the disk key.

The old construction should be explicitly prohibited.

The following relationship must never hold:

```text
disk_key == persisted_field_A XOR persisted_field_B
```

A correct test should require knowledge of the disk PIN and execution of PBKDF2 plus authenticated decryption before the disk key can be recovered.

---

## PIN update power-loss tests

Simulate reset or power loss at every point in:

```text
SETPIN
PUK change
DISK SETPIN
RESTORE
```

After reboot, the store should always be in one of two states:

```text
old state, fully valid

or

new state, fully valid
```

Never:

```text
partially old
partially new
```

---

## Credential metadata tampering tests

Modify persisted fields such as:

```text
profile_id
rp_id_hash
credential_id
public_key
resident
```

and verify that private-key decryption fails if the fields are covered by AAD.

---

## Corrupted disk tests

Test:

```text
corrupt CRC table
corrupt FAT block
corrupt random data block
corrupt encrypted boot block
interrupt CRC-table update
interrupt block write
```

None of these cases should automatically format the disk.

---

## Lock-boundary tests

After `LOCK`, verify:

```text
master key unavailable
disk key wiped
MSC unavailable
pinUvAuthToken invalid
resident discovery cleared
credential-management enumeration cleared
signing denied
credential enrollment denied
```

---

# Recommended remediation order

The issues should be addressed in approximately this order.

1. **Fix disk key wrapping.**

   Replace XOR wrapping plus persisted verifier with authenticated encryption of the disk key.

2. **Redesign the device-PIN / CTAP2-PIN relationship.**

   Avoid allowing the persisted CTAP2 verifier to reveal the same secret used to unwrap credential master key `M`.

3. **Make security-state changes transactional.**

   PIN, PUK, master-key wraps, and restore state should be committed atomically in one A/B store generation.

4. **Fix disk integrity behavior.**

   Verify all blocks if CRC remains, and describe CRC only as corruption detection.

5. **Stop automatic destructive initialization.**

   Corruption should produce a locked/error state, not automatic formatting.

6. **Authenticate credential metadata.**

   Bind important credential metadata to encrypted private keys using AES-GCM AAD.

7. **Use constant-time comparison consistently.**

8. **Invalidate all security-session state on `LOCK`.**

9. **Add CI, sanitizers, and fuzzing.**

10. **Then implement hardware hardening.**

    After the software security model is sound, evaluate:

    - RP2350 Secure Boot
    - signed firmware updates
    - `BOOT_CPROT`
    - boot-ROM restrictions
    - OTP/fuse configuration
    - protection of the firmware signing key

---

# Positive observations

The project already contains several design choices worth keeping.

## A/B flash store

The generation-based A/B store is a good basis for power-loss-safe persistent state.

Factory wipe correctly erases both copies rather than merely writing a new empty generation.

That prevents trivial recovery by selecting the previous record.

## Hardware RNG

Using the Pico SDK hardware RNG through `get_rand_64()` is appropriate for:

- credential IDs
- ECDSA private scalars
- GCM nonces
- salts
- PIN tokens
- master keys

Private P-256 scalars are also validated before use.

## Credential private-key protection

CTAP2 private keys are encrypted at rest using AES-GCM under master key `M`.

Plaintext private-key work buffers are wiped after signing.

The basic hierarchy:

```text
PIN / PUK
    |
    v
master key M
    |
    v
credential private keys
```

is reasonable.

The main problem is the fast CTAP2 PIN verifier exposing the PIN used to protect `M`.

## Backup format

The backup design is stronger than the current disk-key wrapping design.

It uses:

```text
PBKDF2(password, salt)
    |
    v
AES-256-GCM(payload)
```

with random salt and nonce.

The disk-key wrapping should follow the same general model.

## Security documentation

The README clearly states that:

- RP2350 is not a secure element
- Secure Boot is currently not enabled
- physical attackers remain a concern
- OTP/fuse operations are irreversible
- signing-key compromise defeats Secure Boot

This is good and should remain explicit.

---

# Architectural recommendation

A useful long-term security model for Fjaeger would be:

```text
                       +-------------------------+
                       | Device unlock passphrase|
                       +------------+------------+
                                    |
                                  PBKDF2
                                    |
                                    v
                             Master key M
                                    |
                      +-------------+--------------+
                      |                            |
                      v                            v
              CTAP2 credential             backup protection
               private keys

CTAP2 PIN
    |
    +---- CTAP2 clientPin / pinUvAuthToken only


Disk PIN
    |
  PBKDF2
    |
    v
AES-GCM unwrap
    |
    v
random AES-XTS disk key
```

This isolates the three security domains:

```text
device credentials
CTAP2 protocol PIN
encrypted disk
```

A compromise of one verifier should not automatically compromise the others.

---

# Final assessment

Fjaeger is already substantially more structured than a typical prototype USB authenticator.

The main cryptographic components and persistent-state design provide a good foundation.

However, two issues materially undermine the current physical-attacker model:

1. the disk key is directly recoverable from persisted values
2. the CTAP2 PIN verifier permits fast offline recovery of the same PIN that protects the credential master key

These should be considered release-blocking security issues if protection against flash extraction is part of the intended threat model.

The disk-key issue should be fixed first because it is a direct cryptographic key-recovery vulnerability requiring no brute force at all.
