# Fjaeger – fix plan (from findings-current.md)

Originally reviewed at 595ac91. This file now records the disposition of the
findings; `TODO.md` is the active roadmap.

## P1 – FJ-N001 regression (close the test gap) [+ FJ-N009 portion]  ✅ DONE
- Make the host-test AES-GCM stub AAD-sensitive (tag depends on key/nonce/AAD/plaintext; decrypt recomputes+compares before returning plaintext).
- Add regression tests: makeCredential (resident + non-resident) -> persist -> reload -> getAssertion -> decrypt/sign OK.
- Add tamper tests: flip profile_id / rp_id_hash / public_key / resident -> GCM auth must fail (decrypt=false).
- Files: tests/test_ctap2.c, .github/workflows/ci.yml (already runs it).
- Gate: these tests fail on pre-fix code, pass after `e0eee9e`.

## P2 – FJ-N002 split passphrase vs CTAP2 PIN retry/block state  ✅ DONE
- Split `fj_security_t`: `pass_fail/pass_blocked`, `ctap_pin_fail/ctap_pin_blocked`, keep `disk_*`, `puk_fail`.
- Split brute-force contexts: `FJ_BRUTE_PASS`, `FJ_BRUTE_CTAP`, `FJ_BRUTE_DISK`, `FJ_BRUTE_PUK`.
- Serial UNLOCK uses only pass_*; CTAP2 ClientPIN uses only ctap_pin_*; PIN-lock no longer blocks the unlock passphrase and vice versa. PUK clears only intended state (document).
- Files: src/core/keys.h, keys.c, state.c, src/fido/pin.c, console + tests.

## P3 – FJ-N003 CRC before queued writes (msc_disk.c)  ✅ DONE
- Verify on-flash block CRC before applying queued 512B sector writes; refuse if corrupt.

## P4 – FJ-N005 transaction abort real rollback (keys.c)  ✅ DONE
- Add `tx_store` shadow; setters write active store; abort restores; commit promotes.

## P5 – FJ-N006 linker/MSC boundary guard  ✅ DONE
- Add `ASSERT(__flash_binary_end <= XIP+1MiB)` and a named symbol so msc_disk's offset is not a magic constant.

## P6 – FJ-N007 explicit disk recovery command  ✅ DONE
- `DISK FORMAT YES` (unlocked, disk key unwrapped, confirmation token), fail-closed otherwise; no implicit format from DISK UNLOCK.

## P7 – FJ-N004 credProtect  ✅ ACCEPTED POC DESIGN CONSTRAINT
- Status: REMOVAL IS NOT VIABLE. Removing credProtect from GetInfo made
  `ssh-keygen -O resident` fail ("requested feature not supported") — OpenSSH
  requires the extension to permit resident keys. Advertisement restored so
  resident-enroll works.
- Full policy enforcement is deliberately out of scope for the selected
  OpenSSH POC flow: global device unlock is its authorization boundary and the
  device has no internal UV mechanism. Revisit if that security model changes.

## P8 – FJ-N008 document user-presence  ✅ DONE
- Document global-unlock = authorization boundary; LED is feedback, not presence. No code change (by design).
- Document the CTAP2 challenge-response boundary: the host supplies
  `clientDataHash`, Fjaeger signs `authenticatorData || clientDataHash`, and
  no separate custom serial challenge command is provided.

## P9 – FJ-N010 README terminology  ✅ DONE
- Replace stale "CTAP2 PIN reuses device PIN" wording with unlock passphrase / CTAP2 PIN / disk PIN / PUK.

## P10 – FJ-N009 parser fuzzing  ✅ DONE (CTAPHID expansion remains optional)
- CBOR and CTAP2 command fuzz targets run under libFuzzer+ASAN+UBSAN and a GCC
  sanitizer driver in CI. A dedicated CTAPHID transport target remains on the
  active roadmap as an additional coverage improvement.
