#!/usr/bin/env python3
"""Interactive development-only hmac-secret smoke test using system libfido2.

This enrolls a new credential on the selected token. The device must be
unlocked, initialized with HMAC init and configured for pin-button policy.
The caller supplies the test PIN interactively; no outputs are persisted.
"""
import ctypes as c
import getpass
import os
import sys

if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ("--auto", "--armed", "--restore")):
    sys.exit(f"usage: {sys.argv[0]} /dev/hidrawN [--auto|--armed|--restore]")
auto = len(sys.argv) == 3
armed = len(sys.argv) == 3 and sys.argv[2] == "--armed"
restore = len(sys.argv) == 3 and sys.argv[2] == "--restore"
lib = c.CDLL("libfido2.so.1")
ptr, size, integer, string = c.c_void_p, c.c_size_t, c.c_int, c.c_char_p


def api(name, result, *args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, list(args)
    return f


init = api("fido_init", None, integer)
new_dev = api("fido_dev_new", ptr)
new_cred = api("fido_cred_new", ptr)
new_assert = api("fido_assert_new", ptr)
open_dev = api("fido_dev_open", integer, ptr, string)
close_dev = api("fido_dev_close", integer, ptr)
errstr = api("fido_strerr", string, integer)
cred_type = api("fido_cred_set_type", integer, ptr, integer)
cred_hash = api("fido_cred_set_clientdata_hash", integer, ptr, ptr, size)
cred_rp = api("fido_cred_set_rp", integer, ptr, string, string)
cred_user = api("fido_cred_set_user", integer, ptr, ptr, size, string, string, string)
cred_ext = api("fido_cred_set_extensions", integer, ptr, integer)
make = api("fido_dev_make_cred", integer, ptr, ptr, string)
cred_id_ptr = api("fido_cred_id_ptr", ptr, ptr)
cred_id_len = api("fido_cred_id_len", size, ptr)
assert_hash = api("fido_assert_set_clientdata_hash", integer, ptr, ptr, size)
assert_rp = api("fido_assert_set_rp", integer, ptr, string)
assert_cred = api("fido_assert_allow_cred", integer, ptr, ptr, size)
assert_ext = api("fido_assert_set_extensions", integer, ptr, integer)
assert_salt = api("fido_assert_set_hmac_salt", integer, ptr, ptr, size)
assert_up = api("fido_assert_set_up", integer, ptr, integer)
get_assert = api("fido_dev_get_assert", integer, ptr, ptr, string)
secret_ptr = api("fido_assert_hmac_secret_ptr", ptr, ptr, size)
secret_len = api("fido_assert_hmac_secret_len", size, ptr, size)
flags = api("fido_assert_flags", c.c_uint8, ptr, size)


def check(label, value):
    if value != 0:
        raise RuntimeError(f"{label}: {errstr(value).decode()} ({value})")


def buf(data):
    return c.create_string_buffer(data, len(data))


init(0)
dev, cred = new_dev(), new_cred()
if not dev or not cred:
    sys.exit("libfido2 allocation failed")
pin = getpass.getpass("Development FIDO PIN: ").encode()
challenge, user, salt = buf(os.urandom(32)), buf(os.urandom(32)), buf(os.urandom(32))
try:
    check("open", open_dev(dev, os.fsencode(sys.argv[1])))
    check("algorithm", cred_type(cred, -7))
    check("client hash", cred_hash(cred, challenge, 32))
    check("RP", cred_rp(cred, b"fjaeger-test.invalid", b"Fjaeger development test"))
    check("user", cred_user(cred, user, 32, b"test", b"test", None))
    check("extension", cred_ext(cred, 1))
    print("Press and release BOOT when requested for enrollment.", flush=True)
    check("make credential", make(dev, cred, pin))
    cred_id = c.string_at(cred_id_ptr(cred), cred_id_len(cred))
    if not cred_id:
        raise RuntimeError("empty credential ID")
    if armed:
        input("Reboot the device, wait for it to reconnect, then press Enter here: ")
        close_dev(dev)
        check("reopen after reboot", open_dev(dev, os.fsencode(sys.argv[1])))
    elif not restore:
        input("Lock the Fjaeger device using its console, then press Enter here: ")
    outputs = []
    for index in range(2):
        input(f"Press Enter to start assertion {index + 1}: ")
        assertion = new_assert()
        if not assertion:
            raise RuntimeError("assertion allocation failed")
        check("assertion RP", assert_rp(assertion, b"fjaeger-test.invalid"))
        check("assertion hash", assert_hash(assertion, challenge, 32))
        cred_buf = buf(cred_id)
        check("allow credential", assert_cred(assertion, cred_buf, len(cred_id)))
        check("assertion extension", assert_ext(assertion, 1))
        check("hmac salt", assert_salt(assertion, salt, 32))
        if auto:
            check("disable UP", assert_up(assertion, 1))
            if armed and index == 0:
                print("Checking that a reboot leaves armed mode disabled; do not press BOOT.", flush=True)
                denied = get_assert(dev, assertion, None)
                if denied != 0x27:
                    raise RuntimeError(f"unarmed request returned unexpected status {denied}")
                print(f"Unarmed request rejected: {errstr(denied).decode()} ({denied})", flush=True)
                input("Press and release BOOT to arm, then press Enter here: ")
            print(f"Assertion {index + 1}: do not press BOOT.", flush=True)
        else:
            print(f"Press and release BOOT for assertion {index + 1}.", flush=True)
        check("get assertion", get_assert(dev, assertion, None if auto else pin))
        n = secret_len(assertion, 0)
        expected_flags = 0 if auto else 5
        if n != 32 or flags(assertion, 0) & 5 != expected_flags:
            raise RuntimeError("missing output or unexpected UP/UV flags")
        outputs.append(c.string_at(secret_ptr(assertion, 0), n))
        if restore and index == 0:
            input("Complete backup and restore, arm BOOT again, then press Enter here: ")
    if outputs[0] != outputs[1]:
        raise RuntimeError("repeated hmac-secret outputs differ")
    print(f"PASS: assertions returned matching hmac-secret outputs (UP/UV mask {expected_flags})")
finally:
    close_dev(dev)
