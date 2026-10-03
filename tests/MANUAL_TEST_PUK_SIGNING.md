# Manual Test: Verify Signing Works After PUK Unlock

## Purpose
Verify that credential private keys can be decrypted and used for signing after unlocking the device with PUK (instead of PIN).

## What This Tests
- PUK unlock correctly recovers master key M into RAM
- `fj_state_cwk()` returns the correct credential wrapping key after PUK unlock
- `cred_decrypt_private()` can decrypt credential private keys with PUK-recovered M
- CTAP2 `getAssertion` signing succeeds after PUK unlock

## Prerequisites
- Flashed Fjaeger firmware on RP2350 device
- Serial console connected (e.g., `screen /dev/ttyACM0 115200`)
- `ssh-keygen` with FIDO2 support (OpenSSH 8.2+)
- Device HID path known (e.g., `/dev/hidraw2`)

## Test Procedure

### 1. Setup: Create Device PIN, PUK, and Credential

```bash
# Connect to serial console
screen /dev/ttyACM0 115200
```

```
fjaeger> SETPASS test-pass-123
Enter unlock passphrase: ****************
Confirm: ****************
OK unlock passphrase set

fjaeger> UNLOCK test-pass-123
Passphrase: ****************
OK unlocked

fjaeger> PUK test-puk-456789
Enter recovery PUK: ******************
Confirm: ******************
OK recovery PUK set

fjaeger> STATUS
Fjaeger v...
  state: unlocked
  profiles: 1 (active: 0 "Default")
  timeout: 900 seconds
  disk: locked
```

Now create a resident credential (requires device unlocked):

```bash
# Find the FIDO device
ls /dev/hidraw*

# Create a resident ECDSA key
ssh-keygen -t ecdsa-sk -O resident \
  -O device=/dev/hidraw2 \
  -f ~/.ssh/test_puk_key \
  -N '' \
  -C "puk-test-key"

# Expected output:
#   Generating public/private ecdsa-sk key pair.
#   You may need to touch your authenticator to authorize key generation.
#   [device shows cyan LED flash on signing]
#   Your identification has been saved in /home/user/.ssh/test_puk_key
```

Verify credential was created:

```
fjaeger> CREDS LIST
  [00] type=ecdsa-sk application=ssh: resident=yes fp=SHA256:... id=a1b2...
```

### 2. Lock Device and Block PIN

```
fjaeger> LOCK
OK locked

fjaeger> STATUS
  state: locked
  ...
```

Now enter wrong passphrase 5 times to block the PIN:

```
fjaeger> UNLOCK wrong1
Passphrase: ******
ERR bad passphrase (4/5 left)

fjaeger> UNLOCK wrong2
Passphrase: ******
ERR bad passphrase (3/5 left)

fjaeger> UNLOCK wrong3
Passphrase: ******
ERR bad passphrase (2/5 left)

fjaeger> UNLOCK wrong4
Passphrase: ******
ERR bad passphrase (1/5 left)

fjaeger> UNLOCK wrong5
Passphrase: ******
ERR bad passphrase (0/5 left)

fjaeger> UNLOCK test-pass-123
Passphrase: ****************
ERR passphrase blocked, use UNLOCKPUK <puk>
```

Verify PIN is blocked:

```
fjaeger> STATUS
  state: locked (passphrase blocked)
  ...
```

### 3. Unlock with PUK

```
fjaeger> UNLOCKPUK test-puk-456789
Recovery PUK: ******************
OK unlocked via PUK

fjaeger> STATUS
  state: unlocked
  ...
```

### 4. CRITICAL TEST: Try to Sign

This is where the test happens. If `fj_state_cwk()` returns the wrong key after PUK unlock, decryption will fail and signing will be denied.

```bash
# Create a test file to sign
echo "test message" > /tmp/test.txt

# Try to sign with the credential
ssh-keygen -Y sign \
  -f ~/.ssh/test_puk_key \
  -n test \
  /tmp/test.txt
```

**Expected Result (SUCCESS):**
```
Signing file /tmp/test.txt
Write signature to /tmp/test.txt.sig
[device shows CYAN LED flash]
```

**Failure Symptoms:**
- Error: "agent refused operation" → CWK is wrong, decrypt failed
- No cyan LED flash → signing was rejected
- Device returns CTAP2_ERR_INVALID_PARAMETER (0x02) → GCM tag mismatch

### 5. Verify Signature

```bash
# Create allowed_signers file
echo "testkey $(cat ~/.ssh/test_puk_key.pub)" > /tmp/allowed_signers

# Verify the signature
ssh-keygen -Y verify \
  -f /tmp/allowed_signers \
  -I testkey \
  -n test \
  -s /tmp/test.txt.sig \
  < /tmp/test.txt
```

**Expected Output:**
```
Good "test" signature for testkey with ecdsa-sk key SHA256:...
```

### 6. Test Real SSH Login (Optional)

If you have a test SSH server:

```bash
# Add public key to authorized_keys on server
cat ~/.ssh/test_puk_key.pub >> ~/.ssh/authorized_keys

# Try SSH login (device is still unlocked via PUK)
ssh -i ~/.ssh/test_puk_key -o ControlPath=none user@localhost

# Expected: cyan LED flash, login succeeds
```

## Success Criteria

✅ **PASS** if:
1. PUK unlock shows "OK unlocked via PUK"
2. STATUS shows "state: unlocked"
3. `ssh-keygen -Y sign` succeeds with cyan LED flash
4. Signature verifies correctly
5. SSH login succeeds (optional)

❌ **FAIL** if:
1. Signing returns "agent refused operation"
2. No cyan LED flash on signing
3. Device logs show GCM decrypt failure
4. Signature file is not created

## Cleanup

```
fjaeger> LOCK
OK locked

# Or reset completely:
fjaeger> UNLOCKPUK test-puk-456789
Recovery PUK: ******************
OK unlocked via PUK

fjaeger> SETPASS new-password-123
# This re-wraps M with new PIN
```

## What This Proves

This test verifies the complete credential decryption flow after PUK unlock:

1. `fj_state_unlock_puk()` → recovers M via `PBKDF2(PUK) XOR m_enc_puk`
2. `master_available = true` in state.c
3. `fj_state_cwk()` → returns M (the credential wrapping key)
4. `cred_decrypt_private()` → `AES-GCM-decrypt(M, private_key_enc, AAD)`
5. `cred_sign_message()` → `ECDSA-sign(decrypted_private_key, message)`

If any step fails, signing will not work.

## Known Results

Per STATUS.md (2026-09-27):
> **PUK recovers the keys:** after `UNLOCKPUK`, an enrolled resident key still
> signs (the PUK recovers the master key M). `SETPIN <new>` then re-wraps M,
> the old PIN stops working and the key still signs with the new PIN.

This was **physically verified** on the RP2350 dongle.
