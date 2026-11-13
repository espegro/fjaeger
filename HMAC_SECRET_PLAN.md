# Plan: FIDO2 hmac-secret for disk unlock

## Development snapshot (2026-11-13)

This document preserves the design and incremental notes below; references
to components being disconnected describe earlier stages, not current code.
The experimental development implementation now routes hmac-secret over HID,
provides combined backup/restore and credential list/delete, and has been
tested with libfido2, systemd and disposable LUKS2 files on one device.
The tests verified keys without activating a device mapper or testing boot.
The development root is unprotected, OTP provisioning/migration and secure
boot remain unfinished, and PIN-only policy still requires a BOOT press.
Auto/armed permit the explicitly accepted UP=0 unattended behavior. More
recovery, host-reboot and hardware fault testing is required before production.

## Objective and boundaries

Provide a separate LUKS credential that can be used while the device is locked.
Provide independent policies: PIN plus BOOT, PIN only, automatic, and armed
until device reset/power loss. The armed policy requires an explicit BOOT press
before allowing unattended use; it stays armed across host USB reconnects only
if the microcontroller actually continues running. It must not unlock the
device, disk, profiles, or SSH credentials. PIN modes require a configured PIN
and valid authorization; never use dummy PIN mode. Keep existing LUKS slots
and data untouched throughout testing.

## Work

0. Introduce a versioned, read-only OTP provider for an explicitly provisioned
   Fjaeger-specific secret. Do not interpret arbitrary existing OTP values,
   chip identifiers, boot signing hashes, or inaccessible pages as a secret.
   Before any OTP programming, verify the exact RP2350 revision, ROM/errata,
   OTP page allocation, access controls and future secure-boot requirements.
   There is no automatic OTP programming or irreversible lock in development.
   Report the active storage protection mode in STATUS without exposing keys.
   For an existing OTP-protected store, unavailable or invalid OTP fails closed:
   never silently downgrade to the development mode. New unprovisioned test
   devices may use an explicitly identified development mode. Test absent,
   valid, invalid, inaccessible, and changed OTP with a simulated provider.
   Migrate an existing store to OTP only through an explicit, recoverable and
   tested operation; a reboot alone never changes the key or storage mode.
   Define authenticated encrypted backups recoverable without the original OTP
   and verify recovery of existing credential outputs on a replacement device.
1. Implement and test the CTAP2 PIN protocol 1 hmac-secret salt authentication,
   decryption, per-credential HMAC, and encrypted response. Keep it unreachable
   from CTAP until the complete design is implemented and independently tested.
2. Design a separate credential and secret store, including a signing key
   usable while locked. Bind each credential to its RP and ID and use distinct
   domain-separated key material. A PIN-derived wrapping key must be based on
   the material the CTAP PIN protocol actually supplies; document the offline
   attack implications of a low-entropy PIN and the existing PIN verifier.
   A development-only root-record codec and A/B record store are prototyped at
   0x10FEC000–0x10FEE000 (8 records, two 4 KiB sectors). It stores sealed
   records and a versioned root descriptor, and is not connected to FIDO.
   Development mode intentionally stores its root unprotected; simulated OTP
   wraps the root but is not an OTP reader. Expected protection mode must be
   independently protected to resist malicious flash downgrade. Actual OTP
   provider, authorization,
   factory wipe, secure deletion semantics, backup/restore, rollback protection,
   provisioning and OTP migration remain required before activation. CRC is a
   corruption check, not authentication or protection against rollback.
   The separate store implements a tested empty tombstone and interrupted
   erase recovery and is included in journaled factory reset. Individual
   removal writes a validated cleanup marker, then
   erases the preceding A/B slot; initialization resumes an interrupted erase.
   This has host fault-injection coverage but still needs target tests and a
   threat assessment for physical flash remnants and retained backups.
   A versioned AES-GCM backup codec now exports the unwrapped hmac root and
   sealed records, and an empty-store restore can atomically rewrap that root
   under a different device secret. Host tests cover wrong keys, tampering,
   truncation and interrupted restore. This is not yet a user-facing backup:
   password KDF/salt management, lifecycle integration, cross-store atomicity,
   device testing and explicit authorization remain required.
   A standalone password envelope now uses salted PBKDF2 and the codec. Its
   KDF is synchronous and is NOT suitable for the USB task; integrate it as a
   cooperative job before making it user-facing. Its salt and nonce must be
   freshly generated for every backup. It is not yet integrated into the
   existing v2/v3 backup or a combined v4 format.
   `src/core/combined_backup.c` now has an internal authenticated package
   covering both normal keys and the hmac snapshot. Its caller must provide a
   separately KDF-derived key, a unique nonce, authorization, protected buffer
   ownership and cleanup. `combined_password_job.c` adds a password envelope
   with cooperative PBKDF2, salt storage and cancellation; the final AEAD is
   still performed in one step, with target USB latency unmeasured. Host tests
   cover corruption, substitution and cancellation. Neither is wired into
   BACKUP/RESTORE; its native key layout needs explicit future versioning.
   `restore_bundle.c` connects authenticated snapshots and caller-derived
   replacement wraps to the real journal and both stores. Host tests include
   decoding a combined backup, restoring and interrupted writes. The caller
   must still enforce service exclusion, derive secrets, refresh runtime caches
   and handle failure; this operation is not wired into the console.

### Atomic combined restore: required design

The existing two independent A/B stores cannot be committed atomically by
calling their current commit functions in sequence. A failure between those
writes must not expose a mixed SSH/hmac state, erase the recovery source, or
allow normal FIDO operations. Implement and fault-test a shared transaction
journal and staged records before connecting restore:

Prototype status: `src/core/restore_journal.c` reserves two 4 KiB sectors at
0x10FEA000–0x10FEC000 and stores PREPARED/COMMITTED/CLEAN decisions without
secrets. Host tests cover transitions, reinitialization and torn writes. An
invalid non-erased peer fails closed and may need an explicit recovery tool.
Boot now calls the coordinator before starting services; factory reset uses
the wipe journal, while backup/restore does not yet use the coordinator. Its CRC does not
authenticate records against a hostile flash writer.

`src/core/restore_coordinator.c` adds a prototype decision/recovery sequence
around the journal. Host tests use simulated stores and interrupt each stage,
activation, and recovery callback. Boot recovery also has host tests using the
real store implementations; physical flash recovery remains untested.
The reserved store offsets now share `src/core/flash_layout.h`; compile-time
and linker checks protect the existing disk boundary. The existing store
loaders select by generation and must not see staged records as active.
The hmac store now stages a validated snapshot in its own sector at
0x10FE9000–0x10FEA000, bound to transaction ID, generation and SHA-256.
The normal loader ignores this sector. Host tests cover interrupted writes,
discard and reboot with the old store intact. This is not connected to the
user restore; development roots remain plaintext.
The normal key store can also stage an image from an open RAM transaction in
0x10FE1000–0x10FE9000. The caller must first authenticate the backup and set
all replacement verifiers and master wraps, then abort the RAM transaction
after staging. Activation in each store now requires the matching COMMITTED
journal, and host tests exercise interrupted writes and retry on the real
store implementations. PREPARED, COMMITTED and FINALIZING boot recovery is
host tested. FINALIZING verifies the new active images without depending on
staging, erases old inactive A/B copies and removes both staging copies before
writing CLEAN; interrupted erases are host tested. One active copy per store
remains until a later update. A journaled WIPING prototype now erases both
stores and staging, with boot recovery and interrupted-erase host tests. It is
now invoked by PUK-triggered factory reset after clearing live state; failures
halt normal service. Full user-facing restore remains
unfinished; external backups are unaffected by flash erasure.

1. Authenticate and validate the complete backup and both target snapshots
   before modifying either store. Validate keys and device-specific wrapping;
   never place backup passwords, plaintext roots or PINs in the journal.
2. Persist a transaction intent that puts the device into recovery-only mode.
   All normal key use, provisioning, reset, and backup must be unavailable
   until recovery completes. A damaged or unrecognized journal fails closed.
3. Write each new state to an inactive slot as **staged**, with transaction ID,
   generation, size and integrity metadata. Validate each complete flash copy.
   The normal boot loaders must ignore staged records without a committed
   transaction. Retain both previously active copies until a decision is safe.
4. Persist and validate a single commit decision referencing both staged
   records. If power is lost, boot recovery uses the journal to finish the
   exact decision, or restores the old pair while both old copies exist. It
   must never choose independently by highest generation. If a committed
   record is missing/corrupt, fail closed for recovery instead of guessing.
5. Only after both new records are durably active, finalize the transaction,
   clear stale copies as required for deletion, and reopen normal service.
   Test interruption before and after every erase, program and decision write,
   including journal corruption, flash failures and reboot at each boundary.
   Dev-mode CRC protects against accidental corruption, not malicious flash
   modification or replay; OTP/signing and anti-rollback are separate work.

Factory reset spans the same two stores and requires equivalent resumable
coordination; the standalone hmac tombstone is not by itself a global reset.
3. Reserve two 32 KiB A/B slots, with 16 profiles and 64 credentials initially;
   leave room for hmac-secret metadata. Add versioned migration from the v16
   A/B store. Test old
   images, CRCs, interrupted writes and fallback; never treat an unrecognized or
   corrupt existing store as permission to overwrite it. Preserve existing
   credentials, profiles, disk data, presence preference, and PIN retry state.
4. Specify PIN setting, change, unblock, reset and recovery. Rewrap the separate
   key on PIN change without invalidating existing LUKS credentials, or reject
   the change safely. Define a versioned encrypted backup and restoration path,
   including old backups and restoration to a different PIN. Test all failure
   paths and atomicity.
5. Implement CTAP makeCredential/getAssertion extension processing according
   to the FIDO specification, PIN token verification over clientDataHash, and
   user-verification flags. Permit only the new credential type to operate when
   locked; keep SSH credential decryption and signatures gated by the existing
   device lock. No other CTAP operation may consume this authorization.
   The internal `hmac_assertion.c` engine now checks a PIN-verified token,
   policy, RP binding, key agreement and credential encryption, and signs
   authData containing the encrypted hmac-secret output. Host tests verify
   actual P-256 signatures and outputs with simulated PIN/ECDH. It is not
   connected to CTAP request dispatch or the touch state machine. The internal
   `hmac_enroll.c` engine creates and persists a separate credential only
   after an unlocked state and touch. Following user approval, a verified FIDO
   PIN is optional at enrollment so systemd can enroll unattended credentials;
   an explicitly supplied PIN must verify and UV is set only when verified.
   Host tests enroll and then
   assert while locked, with real crypto and simulated PIN/ECDH/touch.
   `hmac_ctap.c` adds an internal CBOR adapter tested through enrollment and
   assertion, including truncated requests and mixed credential ID lengths.
   It remains disabled in the regular dispatcher pending request routing,
   persistent policy and real presence handling. Both stores now expose
   cross-store ID checks; the hmac callback must be registered with normal
   CTAP at activation, and unavailable hmac storage fails closed.
   `hmac_config.c` now stores device policy and expected root mode in an A/B
   region, with host tests for interruption, no implicit root-mode switch and
   volatile armed state. It is included in factory wipe but is not yet wired
   to authorized user configuration, runtime dispatch or real OTP.
   `hmac_runtime.c` now binds that configuration to a boot-scoped policy and
   requires unlocked state, a configured PIN and caller-provided physical
   confirmation to change modes. It remains disconnected from the device main
   loop, physical button, console and CTAP dispatcher.
6. Extend the asynchronous presence flow for the locked credential without
   relaxing the locked-state checks for existing FIDO or console operations.
   Enforce fresh press and release, cancellation, timeout, disconnect and token
   invalidation. Enforce the selected hmac-secret policy independently of the
   existing SSH/WebAuthn presence setting. Never claim UP or UV unless actually
   performed for the relevant request.
   CTAP 2.1 hmac-secret requires rejecting requests with up=false, whereas
   systemd explicitly sends up=false when user presence is disabled. The
   unattended lab modes therefore use a deliberate, user-accepted and clearly
   documented compatibility deviation; only allow it in explicit auto/armed lab policy,
   return UP=0, and test interoperability. Interactive modes remain strict.
7. Test against host-side known vectors and malformed input, authentication
   failures, replay/session transitions, profile and reset boundaries, backup,
   migration, flash faults, fuzzing, and real libfido2 with the device both
   locked and unlocked. Test SSH/WebAuthn regressions and existing data.
8. Only then test a disposable file-backed LUKS2 container with an independent
   recovery passphrase. Test enrollment, reboot, PIN, touch, recovery, and
   initramfs separately before considering any real LUKS volume.
9. Before production, verify signed update and rollback/recovery procedures on
   separate sacrificial hardware. Only after review provision signing identity,
   enable secure boot, and apply appropriate OTP and debug/boot-ROM access
   restrictions. OTP programming and locks are irreversible; never apply
   them automatically or merely because a secret exists.

## Non-goals and open security constraints

No production disk modification or installation on the attached device until
all compatibility and preservation tests pass. Standard FIDO2 PIN protocol 1
transmits only a truncated PIN hash; a flash adversary can brute-force a short
PIN offline given the current verifier. A protocol PIN check alone does not
provide strong at-rest confidentiality against flash extraction. Hardware
secure boot and physical reflash resistance are separate limitations.
An OTP secret without enforced secure boot cannot prevent attacker-supplied
firmware from attempting to use or read it; fallback storage is explicitly
development-only. Automatic/armed modes must not claim that their credentials
are protected by a PIN that is never supplied. PIN-mode protection must also
replace the current fast flash PIN verifier, or the PIN remains guessable from
a flash dump independently of the protected credential.
