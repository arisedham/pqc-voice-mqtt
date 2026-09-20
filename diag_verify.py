#!/usr/bin/env python3
"""
diag_verify.py - find out which data sizes the SSD's verify functions accept.

  sudo python3 diag_verify.py

Why: in test_pqc.py, generate_signature worked on a 312 KB chunk but verify_signature
failed with -13 (P_ERR_SEND_VERIFY_DATA_FAIL). This script signs random data of many
sizes and tries BOTH verify functions on each one, so we can see exactly what works.

Uses only the test slots 0x07 (sign) and 0x06 (verify with key). Takes about 10-20 s.
"""
import ctypes
import os
import re
import sys
import tempfile
import time

import settings
from pqc_sdk import ERRORS, PQCError, open_pqc

# 320044 = one real 10-second audio chunk (44-byte WAV header + 320000 bytes of samples)
SIZES = [32, 64, 1000, 1024, 4096, 4097, 16384, 65536, 131072, 131073, 319488, 320000, 320044, 1048576]
SIGN_SLOT, VERIFY_SLOT = settings.SELFTEST_SLOT, settings.SERVER_VERIFY_SLOT

_libc = ctypes.CDLL(None)
_libc.fflush.argtypes = [ctypes.c_void_p]


def call(func):
    """Run one SDK call and capture what the library prints.
    Returns (result, error_code, milliseconds, sdk_output)."""
    sys.stdout.flush()
    result, code = None, 0
    with tempfile.TemporaryFile() as capture:
        saved_stdout = os.dup(1)
        os.dup2(capture.fileno(), 1)
        t0 = time.perf_counter()
        try:
            result = func()
        except PQCError as e:
            code = e.code
        finally:
            ms = (time.perf_counter() - t0) * 1000
            _libc.fflush(None)
            os.dup2(saved_stdout, 1)
            os.close(saved_stdout)
        capture.seek(0)
        output = capture.read().decode(errors="replace")
    return result, code, ms, output


def describe(outcome, kind):
    """kind = 'sign' or 'verify' (matches the SDK's send_<kind>_data timing line)."""
    result, code, ms, output = outcome
    if code:
        text = f"FAIL {code} {ERRORS.get(code, '?').replace('P_ERR_', '')}"
    elif result is False:
        text = "INVALID (-8)"
    else:
        text = "OK"
    pieces = re.search(rf"send_{kind}_data total: \d+ us, loop_count: (\d+)", output)
    return f"{text}, {ms:.0f} ms, pieces={pieces.group(1) if pieces else '-'}"


def passed(outcome):
    return outcome[1] == 0 and outcome[0] is True


def main():
    pqc = open_pqc(mock="--mock-pqc" in sys.argv)
    print(f"Phison SDK {pqc.version()} | drive {settings.PQC_DEVICE} | "
          f"sign slot 0x{SIGN_SLOT:02X} | verify_with_key slot 0x{VERIFY_SLOT:02X}")

    key = call(lambda: pqc.generate_key_pair(SIGN_SLOT))
    if key[1]:
        print(f"generate_key_pair failed: {describe(key, 'sign')}\n{key[3]}")
        sys.exit(1)
    public_key = key[0]
    print(f"test key pair ready ({len(public_key)}-byte public key)\n")

    print(f"{'bytes':>8} | {'generate_signature':<30} | {'verify_signature':<42} | verify_signature_with_key")
    print("-" * 130)
    verify_ok, verify_fail, with_key_ok, with_key_fail = [], [], [], []
    first_failure = None
    for size in SIZES:
        data = os.urandom(size)
        signed = call(lambda: pqc.sign(data, SIGN_SLOT))
        if signed[1]:
            print(f"{size:>8} | {describe(signed, 'sign'):<30} | (skipped)")
            continue
        signature = signed[0]
        verify = call(lambda: pqc.verify(data, signature, SIGN_SLOT))
        with_key = call(lambda: pqc.verify_with_key(data, signature, public_key, VERIFY_SLOT))
        print(f"{size:>8} | {describe(signed, 'sign'):<30} | {describe(verify, 'verify'):<42} | "
              f"{describe(with_key, 'verify')}")
        (verify_ok if passed(verify) else verify_fail).append(size)
        (with_key_ok if passed(with_key) else with_key_fail).append(size)
        if first_failure is None and not (passed(verify) and passed(with_key)):
            first_failure = (size, verify[3], with_key[3])

    if 320044 in verify_fail or 320044 in with_key_fail:
        data = os.urandom(320044)
        signed = call(lambda: pqc.sign(data, SIGN_SLOT))
        if not signed[1]:
            time.sleep(2)
            verify = call(lambda: pqc.verify(data, signed[0], SIGN_SLOT))
            with_key = call(lambda: pqc.verify_with_key(data, signed[0], public_key, VERIFY_SLOT))
            print(f"\nretry 320044 bytes after a 2 s pause: verify_signature {describe(verify, 'verify')} | "
                  f"verify_signature_with_key {describe(with_key, 'verify')}")

    print("\nSUMMARY")
    print(f"  verify_signature          OK for: {verify_ok or 'none'}")
    print(f"                            FAIL for: {verify_fail or 'none'}")
    print(f"  verify_signature_with_key OK for: {with_key_ok or 'none'}")
    print(f"                            FAIL for: {with_key_fail or 'none'}")
    if first_failure:
        size, verify_output, with_key_output = first_failure
        print(f"\nSDK messages for the first failing size ({size} bytes):")
        print("  verify_signature:\n    " + "\n    ".join(verify_output.strip().splitlines() or ["(none)"]))
        print("  verify_signature_with_key:\n    " + "\n    ".join(with_key_output.strip().splitlines() or ["(none)"]))


if __name__ == "__main__":
    main()
