# Fjaeger – fix plan (from findings-current.md)

Reviewed: 595ac91. FJ-N001 code fix landed in `e0eee9e`. Plan below, in the
suggested order. Each step verified with host tests (incl. ASAN/UBSAN) + a
firmware build, then committed.

## P1 – FJ-N001 regression (close the test gap) [+ FJ-N009 portion]
- Make the host-test AES-GCM stub AAD-sensitive (tag depends on key/nonce/AAD/plaintext; decrypt recomputes+compares before returning plaintext).
- Add regression tests: makeCredential (resident + non-resident) -> persist -> reload -> getAssertion -> decrypt/sign OK.
- Add tamper tests: flip profile_id / rp_id_hash / public_key / resident -> GCM auth must fail (decrypt=false).
- Files: tests/test_ctap2.c, .github/workflows/ci.yml (already runs it).
- Gate: these tests fail on pre-fix code, pass after `e0eee9e`.

## P2 – FJ-N002 split passphrase vs CTAP2 PIN retry/block state
- Split `fj_security_t`: `pass_fail/pass_blocked`, `ctap_pin_fail/ctap_pin_blocked`, keep `disk_*`, `puk_fail`.
- Split brute-force contexts: `FJ_BRUTE_PASS`, `FJ_BRUTE_CTAP`, `FJ_BRUTE_DISK`, `FJ_BRUTE_PUK`.
- Serial UNLOCK uses only pass_*; CTAP2 ClientPIN uses only ctap_pin_*; PIN-lock no longer blocks the unlock passphrase and vice versa. PUK clears only intended state (document).
- Files: src/core/keys.h, keys.c, state.c, src/fido/pin.c, console + tests.

## P3 – FJ-N003 CRC before queued writes (msc_disk.c)
- Verify on-flash block CRC before applying queued 512B sector writes; refuse if corrupt.

## P4 – FJ-N005 transaction abort real rollback (keys.c)
- Add `tx_store` shadow; setters write active store; abort restores; commit promotes.

## P5 – FJ-N006 linker/MSC boundary guard
- Add `ASSERT(__flash_binary_end <= XIP+1MiB)` and a named symbol so msc_disk's offset is not a magic constant.

## P6 – FJ-N007 explicit disk recovery command
- `DISK FORMAT YES` (unlocked, disk key unwrapped, confirmation token), fail-closed otherwise; no implicit format from DISK UNLOCK.

## P7 – FJ-N004 credProtect
- Status: REMOVAL IS NOT VIABLE. Removing credProtect from GetInfo made
  `ssh-keygen -O resident` fail ("requested feature not supported") — OpenSSH
  requires the extension to permit resident keys. Advertisement restored so
  resident-enroll works.
- Open: implement credProtect (parse extensions 0x06 -> per-credential policy
  persisted in the AAD; enforce UV policies in getAssertion). Deferred; needs
  a real UV path or explicit UV-required rejection.

## P8 – FJ-N008 document user-presence
- Document global-unlock = authorization boundary; LED is feedback, not presence. No code change (by design).

## P9 – FJ-N010 README terminology
- Replace stale "CTAP2 PIN reuses device PIN" wording with unlock passphrase / CTAP2 PIN / disk PIN / PUK.

## P10 – FJ-N009 remainder + fuzzing
- Parser fuzz targets (cbor, CTAPHID, makeCredential, getAssertion, ClientPIN, credMgmt); keep ASAN/UBSAN.
