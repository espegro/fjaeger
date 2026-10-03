# Security Review - 2026-10-03

## Summary

Security analysis of Fjaeger's authentication and credential management logic, with focus on potential vulnerabilities in lock/unlock state handling, PIN/PUK recovery, and credential wrapping key (CWK) management.

## Findings

### ✅ VERIFIED: CWK Recovery After PUK Unlock (False Alarm)

**Initial Concern:** Whether PUK unlock correctly recovers the credential wrapping key (CWK) needed to decrypt private keys.

**Analysis:**
- CWK is the master key M, not `PBKDF2(PIN)`
- PIN unlock: `M = m_enc_pin XOR PBKDF2(PIN, salt_pin)`
- PUK unlock: `M = m_enc_puk XOR PBKDF2(PUK, salt_puk)`
- Both methods recover the **same M**

**Verification:**
- `tests/test_security.c:328` confirms: `assert(memcmp(m_orig, m_puk, 32) == 0)`
- Physically verified 2026-09-27 per STATUS.md: "after UNLOCKPUK, an enrolled resident key still signs"

**Status:** ✅ No vulnerability. Design is correct.

---

### 🔴 FIXED: Pin Token Not Securely Zeroed on Reset

**Issue:** `fj_pin_reset_token()` only set `token_valid = false` but did not clear the 32-byte `pin_token` buffer from memory.

**Impact:** MEDIUM
- An attacker with memory access could recover a previously valid pinUvAuthToken
- Token is already regenerated on each `getPinToken` and invalidated on every lock
- This only closes a memory-residency window between lock and reuse

**Root Cause:**
```c
void fj_pin_reset_token(void) {
    token_valid = false;  // ← buffer not cleared!
}
```

**Fix (commit 55c8ce8):**
```c
void fj_pin_reset_token(void) {
    fj_secure_zero(pin_token, sizeof(pin_token));
    token_valid = false;
}
```

Also fixed `auth_priv` to use `fj_secure_zero` instead of `memset`.

**Test:** `tests/test_pin_token_scrub.c` verifies buffer is zeroed.

**Status:** ✅ Fixed and tested.

---

### 🟡 OPEN: No pinUvAuthParam Verification in CTAP2 Operations

**Issue:** `makeCredential` and `getAssertion` check only device unlock state, not whether the client has obtained a valid pinToken via `getPinToken`.

**Code:**
```c
// src/fido/ctap2.c:670
if (fj_state_get() != FJ_STATE_UNLOCKED) {
    return ctap_error(out, cap, ERR_OPERATION_DENIED);
}
// ← No pinUvAuthParam verification!
```

**CTAP2 Spec:** Operations should verify the `pinUvAuthParam` HMAC signature to prove the client obtained the pinToken.

**Current Behavior:**
- Any client can perform operations if device is unlocked (via serial console)
- CTAP2 PIN is only verified during `getPinToken`, not during credential operations
- Global device unlock (serial passphrase) is the authorization boundary

**Impact:** MEDIUM
- Deviation from CTAP2 spec
- A local attacker with HID access can perform operations without knowing the CTAP2 PIN if device is unlocked via serial
- This is a **documented design choice** per README.md:
  > "Global device unlock is the user authorization boundary"

**Status:** 🟡 Known deviation from spec. Documented as intentional for the POC workflow.

**Recommendation:** Consider adding `pinUvAuthParam` verification for full CTAP2 compliance if the threat model changes.

---

### 🟢 LOW: Brute-Force Backoff Does Not Survive Reboot

**Issue:** The RAM-only exponential backoff can be reset by rebooting the device between attempts.

**Code Comment (INCORRECT):**
```c
// src/core/state.c:52-53
/* The delay is RAM-only and based on the monotonic microsecond counter,
   so it cannot be reset by a reboot */  // ← This is false!
```

**Actual Behavior:**
- `brute_fail_count[]` and `brute_allowed_at[]` are static globals (RAM-only)
- A reboot clears them back to zero
- The exponential backoff (2s → 30s) is lost

**Mitigation:**
- Persistent retry counters (`FJ_MAX_PIN_FAILS = 5`) still enforce the hard limit
- After 5 wrong attempts, the PIN is permanently blocked until PUK recovery
- Backoff only slows down the first 5 attempts

**Impact:** LOW
- An attacker can avoid the 2s→30s delays by rebooting between attempts
- But they still only get 5 total attempts before permanent block
- Real-world impact: saves ~60 seconds over 5 attempts

**Fix:** Update comment to reflect reality.

**Status:** 🟢 Low risk. Recommend fixing documentation.

---

### 🟢 LOW: Confusing Error Messages (Dummy Mode)

**Issue:** When CTAP2 PIN is not configured (dummy mode), `getPinToken` succeeds with any PIN, but `makeCredential` may fail with `OPERATION_DENIED` if device is locked. The client cannot distinguish between:
1. Device is locked (passphrase not entered on serial)
2. CTAP2 PIN is wrong

**Example Flow:**
1. User has not set a CTAP2 PIN (dummy mode active)
2. Client calls `getPinToken` with any PIN → success (dummy mode accepts it)
3. Client calls `makeCredential` → fails with `ERR_OPERATION_DENIED` (device locked)
4. Client sees: "operation denied" but doesn't know **why**

**Impact:** LOW - Usability issue, not a security vulnerability.

**Recommendation:**
- Consider returning a more specific error code when device is locked
- Or document this behavior clearly for integrators

**Status:** 🟢 Known limitation of the POC design.

---

## Test Coverage

All host tests pass:

```
✓ test_security        - PIN/PUK recovery, lockout, factory wipe
✓ test_ctap2           - CBOR parsing, resident credentials
✓ test_profile         - Profile isolation, credential binding
✓ test_profile_erase   - Cache consistency on profile deletion
✓ test_hmac            - PBKDF2/HMAC-SHA256 against RFC vectors
✓ test_pin_token_scrub - NEW: Verify secure-zero on token reset
```

Run with: `scripts/run_all_tests.sh`

## Manual Testing (Hardware)

For physical verification of PUK unlock → signing flow, see:
- `tests/MANUAL_TEST_PUK_SIGNING.md` - Detailed test procedure
- `scripts/test_puk_signing.sh` - Semi-automated test harness

**Known Physical Verification (per STATUS.md):**
- 2026-09-27: PUK recovery confirmed to recover M and preserve signing ability
- 2026-09-28: Resident credential signing verified end-to-end after PUK unlock

## Recommendations

### High Priority
1. ✅ **DONE** (55c8ce8): Secure-zero `pin_token` on reset

### Medium Priority
2. Fix incorrect comment about brute-force backoff surviving reboot
3. Consider implementing `pinUvAuthParam` verification for CTAP2 compliance

### Low Priority
4. Improve error messages to distinguish device-locked vs PIN-blocked states
5. Add documentation about dummy mode behavior

## Security Model Summary

**Authentication Layers:**
1. **Device unlock (serial):** Passphrase protects master key M
2. **CTAP2 PIN (HID):** Independent PIN for FIDO2 protocol (dummy mode if not set)
3. **Recovery PUK:** Can unlock device and recover M without knowing passphrase

**At-Rest Protection:**
- Credentials encrypted with M (AES-GCM)
- M wrapped by both PIN and PUK (PBKDF2-HMAC-SHA256, 100k iterations)
- Persistent retry counters prevent brute-force (5 attempts → block)
- Exponential backoff (RAM-only, 2s → 30s cap) slows online attacks

**Key Material Lifecycle:**
- M generated randomly on first passphrase set
- M held in RAM only while unlocked
- M securely zeroed on lock
- PIN/PUK can be changed without losing M (re-wrap operation)

**Authorization Boundary:**
- Global device unlock (passphrase) is the primary security boundary
- CTAP2 PIN is a protocol requirement but not separately enforced in operations
- This is documented as an intentional POC design choice

## Conclusion

No critical vulnerabilities found. One medium-severity issue (pin_token scrubbing) has been fixed and tested. Remaining items are either low-priority improvements or documented design trade-offs for the POC scope.

The credential wrapping key (CWK) recovery after PUK unlock works correctly, as verified by both unit tests and physical hardware testing.
