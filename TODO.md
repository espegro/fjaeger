# Fjaeger roadmap

This roadmap covers the current hardening findings and optional Ed25519
credential support. Fjaeger is still a POC: persisted data from older firmware
formats is disposable, and store migrations/backward compatibility are
deliberately out of scope until the on-flash format is declared stable.

## P1 - Cryptographic and parser hardening

- [x] Use `mbedtls_gcm_auth_decrypt()` and clear plaintext output when
      authentication fails.
- [x] Add `fj_secure_zero()` and use it for private keys, KDF state, passphrases,
      PUKs, backup plaintext and completed/failed cooperative jobs.
- [x] Limit recursive CBOR nesting and reject lengths/counts that do not fit
      the target's `size_t`.
- [x] Generate and validate the ClientPIN P-256 key-agreement scalar with the
      existing private-key generator.

## P1 - Build and regression coverage

- [x] Add a Pico SDK 2.2.0 ARM firmware-build CI job and retain ELF/UF2
      artifacts. Tightening third-party SDK warnings to errors remains separate.
- [x] Ensure CI exercises the linker assertion protecting the MSC boundary.
- [x] Add a focused test for authenticated-decrypt failure/output clearing.
- [x] Add focused tests for CBOR nesting/count limits and completed job
      scrubbing.
- [ ] Add a CTAPHID fuzz target; keep CBOR/CTAP2 ASAN+UBSAN fuzz smoke tests.

## P2 - CTAP2 semantics for the selected workflow

- [x] Report `clientPin` false until a CTAP2 PIN has been configured.
- [x] Keep CDC as the documented PIN administration interface; ClientPIN
      `setPIN`/`changePIN` are deliberately omitted for the selected flow.
- [x] Keep the current `credProtect` compatibility behaviour documented as a
      deliberate OpenSSH-flow constraint. Revisit only if the product's UV
      model changes.
- [x] Keep global unlock as the documented user-presence boundary unless
      hardware with a button/touch input is adopted.

## P2 - MSC reliability

- [x] Track dirty CRC-table pages and avoid rewriting all four flash sectors
      for every data-block update.
- [ ] Design A/B or journalled CRC metadata so power loss cannot leave a new
      data block paired with an old CRC.
- [ ] Add reset/power-loss fault-injection tests around data and CRC commits.

## P2 - Ed25519 / `ed25519-sk`

- [x] Select and vendor/pin Monocypher 4.0.3's constant-time Ed25519
      implementation suitable for Cortex-M33 (Mbed TLS in the current Pico SDK
      does not provide the required EdDSA signing path).
- [x] Add crypto wrappers for key generation, public-key derivation and signing,
      with known-answer and negative tests.
- [x] Accept both ES256 (`-7`) and EdDSA (`-8`) in `pubKeyCredParams`, and
      select the first mutually supported algorithm.
- [x] Encode Ed25519 public keys as COSE OKP (`kty=1`, `alg=-8`, `crv=6`).
- [x] Persist the credential algorithm without changing the current store
      layout if possible: retain `0x04 || X || Y` for P-256 and use an explicit
      marker plus 32-byte public key in the existing 65-byte field for Ed25519.
- [x] Bind the algorithm/complete public-key field through the existing GCM AAD.
- [x] Sign `authenticatorData || clientDataHash` directly with Ed25519 and
      return its raw 64-byte signature; retain SHA-256 plus DER encoding only
      for ES256.
- [x] Update assertion discovery, credential management, backup/restore,
      host stubs, fuzzing and documentation for mixed credential algorithms.
- [x] Verify non-resident and resident `ssh-keygen -t ed25519-sk` enrollment,
      `ssh-keygen -K` and `ssh-keygen -Y sign/verify` on the physical key.
- [ ] Verify an actual SSH login with the physical key against a disposable
      test account/server.

## P3 - Policy and cleanup

- [ ] Raise or explicitly document minimum entropy expectations for the disk
      PIN, recovery PUK and backup password.
- [x] Remove duplicate constants and stale status text/documentation.
- [x] Update `FIX_PLAN.md` so completed fuzz work and deliberate design choices
      match the current implementation.

## Hardware test safety

- [x] Build and run all host tests before flashing.
- [ ] Save any wanted backup before the first destructive test.
- [ ] Use the connected blankable key for staged smoke tests, then deliberate
      store-version, reset-during-write and full-wipe testing.
