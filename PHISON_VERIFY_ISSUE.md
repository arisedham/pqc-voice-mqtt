# KAZ verification always fails with -13 on E31T PQC SSD (Linux SDK V3)

## Summary

On our Phison E31T PQC SSD, `generate_key_pair` and `generate_signature` work, but every
signature verification fails with **-13 `P_ERR_SEND_VERIFY_DATA_FAIL`**.

This happens with the **unmodified Phison `demo_app`** from the V3 Linux package (option 2,
"Generate Signature + Verify Signature"). Both `verify_signature` and `verify_signature_with_key`
fail at every data size we tried (32 bytes to 1 MB).

## Environment

| Item | Value |
|---|---|
| SSD | Phison E31T PQC SSD, 512 GB, PCI ID `1987:5031`, serial `E0BE19670A7600000390` |
| Firmware | `EVFM00.0-0002` (from `get_firmware_version`; Linux sysfs shows `EVFM00.0`) |
| Device node | `/dev/nvme1n1` (the operating system is on a separate NVMe drive) |
| SDK | PQC-LIBR V3, `pqc_linux_so.tar.gz` (MD5 `4eea8e006466a7fdc23984e98127b9a0`), `libphison_agent.so.1.1.0`, `get_agent_version()` returns `1.1.0` |
| Test program | Prebuilt `demo_app` 1.1.0 from the same package, started with `sudo ./run_demo.sh` |
| Host | ASUS ExpertBook B1403CVA, Ubuntu 24.04.5 LTS, kernel 7.0.0-31-generic, x86_64 |
| Password | Default (32 bytes `0x00`-`0x1F`); authentication succeeds |

## Steps to reproduce

1. `cd pqc_linux_so/demo_project && sudo ./run_demo.sh`
2. Select index `1` (`/dev/nvme1n1`)
3. Choose `A` and generate a 42 KB random file
4. Choose `2` and accept all defaults (file 1, default password, key slot `0x02`, run count 1)

## Result

```
=== Step 5: Generating key pair ===
[LOG] Generating key pair at slot 0x02 with algorithm 0x30...
[LOG] Key pair generated successfully!

=== Step 6: Generating signature ===
[TIMING] send_sign_data total: 99352 us, loop_count: 1, avg: 99352 us
[TIMING] pHSM_get_signature: 450 us
[TIMING] copy_signature: 18 us
[TIMING] pHSM_end_session: 307 us
[TIMING] generate_signature total: 467833 us
[LOG] Signature generated successfully!

=== Step 7: Verifying signature ===
[LOG] Verifying signature with key slot 0x02...
[TIMING] verify_signature start_session: 2080 us
[TIMING] perform_signature_verification: 418 us
[TIMING] verify_signature end_session: 177 us
[TIMING] verify_signature total: 2714 us

[LOG] Example FAILED: Verify signature failed at iteration 1 (error: -13)
```

Expected: `Signature verified successfully!`

## Additional tests

We called the same library directly (Python `ctypes`, default password):

- **Data sizes** 32, 64, 1000, 1024, 4096, 4097, 16384, 65536, 131072, 131073, 319488, 320000,
  320044 and 1048576 bytes: `generate_signature` succeeds for every size (1 to 8 transfer pieces).
  `verify_signature` (same slot) and `verify_signature_with_key` (public key injected into another
  slot) return -13 for every size.
- **Key slots tested:** `0x02` (demo_app), `0x07` (sign and same-slot verify), `0x06`
  (`verify_signature_with_key`).
- **Retry:** verifying again after a 2-second pause gives the same -13.
- **Where it fails:** verification fails about 0.3-0.6 ms into `perform_signature_verification`.
  The library's `[TIMING] send_verify_data ...` and `[TIMING] pHSM_get_verify_result ...` lines are
  never printed, so the first verify-data transfer appears to be rejected.

## Questions

1. Does firmware `EVFM00.0-0002` support KAZ signature verification with Linux SDK V3 (1.1.0)?
   If not, which firmware or library version do we need?
2. Is there a known issue, or a required setup step before verification (key attributes,
   slot configuration, drive state)?
3. Can you provide a fixed library or firmware? We have a POC demo on 30 September 2026,
   so an estimated date would help us plan.

Contact: [your name, company, email]
