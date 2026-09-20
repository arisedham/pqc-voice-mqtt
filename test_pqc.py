#!/usr/bin/env python3
"""
test_pqc.py - check what the Phison PQC SSD on THIS machine can do.

  sudo python3 test_pqc.py

Runs the same API sequence as Phison's demo document:
  is_phison_device -> get_firmware_version -> generate_key_pair -> generate_signature
  -> verify_signature -> verify_signature_with_key -> tamper test (must FAIL to verify)

It keeps going after a failure and ends with one line per role:
  EDGE   needs: key pair + signing
  SERVER needs: verify_signature_with_key + the tamper test

Only the test slots (SELFTEST_SLOT, SERVER_VERIFY_SLOT) are used, so the edge device's
identity key is never touched.
"""
import os
import sys
import time

import settings
from pqc_sdk import KAZ_PUBLIC_KEY_LENGTH, KAZ_SIGNATURE_LENGTH, PQCError, open_pqc

GREEN, RED, RESET = "\x1b[32m", "\x1b[31m", "\x1b[0m"
problems = []


def check(name, func, judge):
    """Run one SDK call. judge(result) -> (passed, detail). Returns (passed, result)."""
    t0 = time.perf_counter()
    try:
        result, error = func(), None
    except PQCError as e:
        result, error = None, str(e)
    ms = (time.perf_counter() - t0) * 1000
    if error:
        problems.append(f"{name}: {error}")
        passed, detail = False, "error (details below)"
    else:
        passed, detail = judge(result)
    mark = f"{GREEN}[ OK ]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    print(f"  {mark} {name:<42} {detail:<34} {ms:8.1f} ms")
    return passed, result


def verdict(passed):
    return f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"


def main():
    pqc = open_pqc(mock="--mock-pqc" in sys.argv)
    slot, verify_slot = settings.SELFTEST_SLOT, settings.SERVER_VERIFY_SLOT
    print(f"Phison SDK {pqc.version()} | drive {settings.PQC_DEVICE} | test slot 0x{slot:02X}\n")

    device_ok, _ = check("is_phison_device + get_firmware_version", pqc.check_device,
                         lambda firmware: (True, f"firmware {firmware}"))
    if not device_ok:
        print(f"\n{RED}{problems[0]}{RESET}")
        sys.exit(1)

    keygen_ok, public_key = check("generate_key_pair", lambda: pqc.generate_key_pair(slot),
                                  lambda key: (len(key) == KAZ_PUBLIC_KEY_LENGTH, f"{len(key)}-byte public key"))

    data = os.urandom(settings.SAMPLE_RATE * settings.CHANNELS * 2 * settings.CHUNK_SECONDS)  # = one audio chunk
    sign_ok, signature = False, None
    if keygen_ok:
        sign_ok, signature = check(f"generate_signature ({len(data) // 1024} KB)", lambda: pqc.sign(data, slot),
                                   lambda sig: (len(sig) == KAZ_SIGNATURE_LENGTH, f"{len(sig)}-byte signature"))

    with_key_ok = tamper_ok = False
    if sign_ok:
        check("verify_signature (same slot)", lambda: pqc.verify(data, signature, slot),
              lambda valid: (valid, "valid" if valid else "INVALID"))
        with_key_ok, _ = check("verify_signature_with_key (like server)",
                               lambda: pqc.verify_with_key(data, signature, public_key, verify_slot),
                               lambda valid: (valid, "valid" if valid else "INVALID"))
        if with_key_ok:
            tampered = bytearray(data)
            tampered[1000] ^= 0x01  # flip one bit
            tamper_ok, _ = check("tamper test (1 bit changed)",
                                 lambda: pqc.verify_with_key(bytes(tampered), signature, public_key, verify_slot),
                                 lambda valid: (not valid, "rejected (good)" if not valid else "ACCEPTED (bad!)"))

    edge_ok = keygen_ok and sign_ok
    server_ok = with_key_ok and tamper_ok
    print()
    print(f"  EDGE functions   (key pair + signing):         {verdict(edge_ok)}")
    print(f"  SERVER functions (verify_signature_with_key):  {verdict(server_ok)}")

    if problems:
        print("\nDetails:")
        for problem in problems:
            print(f"  - {problem}")
    if sign_ok and not server_ok:
        print("\nVerification does not work on this SSD. Phison's own demo_app fails the same way on firmware")
        print("EVFM00.0-0002 (see PHISON_VERIFY_ISSUE.md). This SSD can still be used by the EDGE, which only signs.")
    sys.exit(0 if edge_ok and server_ok else 1)


if __name__ == "__main__":
    main()
