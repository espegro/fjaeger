# Gaps Analysis - What's Missing in Current Build

Analysis date: 2026-10-03 (firmware 582dcb9)

## 🔴 Critical Security Gaps

### 1. No Hardware Secure Element
**Status:** Fundamental limitation of RP2350 platform

**Issue:** 
- Private keys stored in ordinary external flash
- No tamper resistance
- Physical attacker with lab equipment can dump flash
- At-rest protection relies only on PIN/PUK strength (PBKDF2)

**Mitigation:**
- RP2350 Secure Boot + fuses could help (see below)
- Strong PIN/PUK requirements (currently not enforced)
- Document as POC/development platform limitation

### 2. No Secure Boot / Flash Protection
**Status:** Not implemented (requires one-time-programmable fuses)

**Missing:**
- Signed firmware enforcement
- `BOOT_CPROT` fuses to prevent flash dumps
- `BROM_LOCK` to lock down boot ROM

**Impact:**
- Anyone can re-flash arbitrary firmware via BOOTSEL
- Flash can be dumped over BOOTSEL
- "Seal" policy features are not enforced

**Risk:** HIGH for production use, acceptable for POC

### 3. No User Presence Detection
**Status:** Design limitation (no button hardware)

**Issue:**
- "Device unlocked" is the authorization boundary
- No per-signature touch confirmation
- CTAP2 UP (user presence) not enforced

**Impact:**
- Malware on unlocked PC can sign without user knowledge
- Deviates from FIDO2 best practices

---

## 🟡 Medium Priority Gaps

### 4. CTAPHID Fuzz Testing
**Status:** TODO (P1 in TODO.md)

**Missing:**
- CTAPHID transport layer fuzzer
- Only CBOR/CTAP2 command fuzzing exists

**Risk:** MEDIUM - transport bugs could crash device or leak info

### 5. MSC Power-Loss Resilience
**Status:** TODO (P2 in TODO.md)

**Missing:**
- A/B or journalled CRC metadata
- Power loss during write can corrupt CRC-table consistency
- Fault-injection tests

**Current State:**
- Data blocks have CRC protection
- But CRC table itself is not atomic
- Power loss at wrong moment → metadata corruption

**Risk:** MEDIUM - data loss on power failure during write

### 6. No pinUvAuthParam Verification
**Status:** Documented design choice (SECURITY_REVIEW.md)

**Missing:**
- CTAP2 operations don't verify pinUvAuthParam HMAC
- Only check device unlock state

**Impact:**
- Deviation from CTAP2 spec
- Client with HID access can operate if device unlocked via serial
- Not a vulnerability if threat model accepts this

### 7. Ed25519 SSH Login Not Verified
**Status:** TODO (P2 in TODO.md, line 69)

**Current State:**
- Ed25519 credentials work (makeCredential, sign, verify)
- `ssh-keygen -t ed25519-sk` tested
- But actual SSH login not physically verified

**Missing:** Test against real SSH server with ed25519-sk key

---

## 🟢 Low Priority / Quality Improvements

### 8. Incorrect Brute-Force Comment
**Status:** TODO (SECURITY_REVIEW.md)

**Issue:** 
```c
// src/core/state.c:52-53
/* so it cannot be reset by a reboot */  // ← This is false!
```

**Reality:** RAM-only backoff IS reset by reboot

**Fix:** Update comment to match reality

### 9. No Minimum Entropy Requirements
**Status:** TODO (P3 in TODO.md)

**Missing:**
- No enforced minimum for disk PIN, PUK, backup password
- Currently accepts any length within range

**Current Limits:**
- Device PIN: 4-32 chars (should be 8+)
- Disk PIN: 4-32 chars (weak!)
- PUK: 8-64 chars (OK)
- Backup password: 8-64 chars (OK)

**Recommendation:** Enforce 8+ chars for all secrets

### 10. Confusing Error Messages (Dummy Mode)
**Status:** LOW (SECURITY_REVIEW.md)

**Issue:** 
- Dummy CTAP2 PIN mode accepts anything
- But operations still fail if device locked
- Client can't distinguish lock vs PIN error

**Fix:** Better error codes or documentation

### 11. No Persistent Signature Counter
**Status:** Known limitation (README.md)

**Current:** Counter is always 0
**FIDO2 Spec:** Should be monotonic and persistent

**Impact:** LOW - counter is advisory, not security-critical

### 12. Limited Credential Storage
**Status:** Design choice

**Current:** Max 12 credentials total (all profiles)
**Typical:** Commercial keys store 25-100

**Impact:** LOW for POC, may need expansion for real use

---

## ⚪ Missing Features (Not Security Issues)

### 13. U2F/CTAP1 Support
**Status:** Deliberately disabled

**Current:** Only CTAP2 implemented
**Missing:** Legacy U2F for older browsers

**Impact:** Can't use with old WebAuthn implementations

### 14. WebAuthn Testing
**Status:** Only OpenSSH tested physically

**Missing:**
- Browser WebAuthn testing (Chrome, Firefox)
- Multiple OS testing (Linux only so far)
- Multiple concurrent FIDO devices

### 15. Attestation
**Status:** Format is "none"

**Missing:**
- No X.509 certificate chain
- No batch attestation
- No anonymization CA

**Impact:** Some enterprise environments require attestation

### 16. Additional CTAP2 Extensions
**Status:** Only credProtect advertised (not enforced)

**Missing:**
- hmac-secret
- credBlob
- largeBlobKey
- minPinLength

**Impact:** LIMITED - OpenSSH doesn't need these

---

## 📊 Summary by Priority

### Critical (Production Blockers)
1. ❌ No hardware secure element
2. ❌ No secure boot / flash protection
3. ❌ No user presence button

### High Priority (Should Fix)
4. ☐ CTAPHID fuzz testing
5. ☐ MSC power-loss resilience
6. ☐ Minimum entropy requirements

### Medium Priority (Nice to Have)
7. ☐ pinUvAuthParam verification
8. ☐ Ed25519 SSH login verification
9. ☐ Brute-force comment fix
10. ☐ Better error messages

### Low Priority (Quality of Life)
11. ☐ Persistent signature counter
12. ☐ Larger credential storage
13. ☐ WebAuthn/browser testing

### Won't Fix (Design Choices)
- U2F/CTAP1 (CTAP2 only)
- Attestation (none format)
- Additional extensions (not needed for SSH)

---

## 🎯 Recommended Next Steps

### For Production Readiness:
1. **Hardware:** Add user presence button
2. **Security:** Implement Secure Boot + CPROT fuses
3. **Entropy:** Enforce minimum 8+ chars for all secrets
4. **Testing:** Add CTAPHID fuzzer
5. **Reliability:** A/B CRC metadata for power-loss protection

### For POC/Development:
✅ Current state is acceptable with documented limitations
- Clearly label as "POC / development platform"
- Warn users about physical security limitations
- Document that keys are not tamper-resistant

### Quick Wins (Low Effort, High Value):
1. Fix brute-force comment (5 min)
2. Add minimum entropy checks (1 hour)
3. Verify ed25519-sk SSH login (30 min)
4. Add CTAPHID fuzzer (1 day)

---

## ⚠️ What This Build Should NOT Be Used For

**Do NOT use for:**
- Production security keys holding real secrets
- High-value accounts (GitHub, banking, corporate)
- Environments requiring tamper resistance
- Deployments requiring FIPS/Common Criteria compliance

**OK to use for:**
- Development and testing
- Learning FIDO2/CTAP2 protocols
- OpenSSH sk-key experimentation
- Prototyping security key workflows

---

## ✅ What Works Well

**Strengths of current implementation:**
1. ✓ Solid CTAP2 core (makeCredential, getAssertion, resident keys)
2. ✓ Both ES256 and Ed25519 credentials
3. ✓ Profile isolation works correctly
4. ✓ PIN/PUK recovery preserves keys (M wrapping)
5. ✓ Encrypted backup/restore
6. ✓ Persistent encrypted drive (12 MiB)
7. ✓ Good test coverage (6 host tests + physical verification)
8. ✓ Clear documentation and security review

**This is a solid POC foundation** - the missing pieces are mostly about
hardening for production, not core functionality.
