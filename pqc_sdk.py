"""
pqc_sdk.py - small Python wrapper around Phison's libphison_agent.so.

All KAZ-SIGN operations happen INSIDE the SSD. The private key never leaves it;
Python only ever sees public keys (118 bytes) and signatures (354 bytes).

Real mode needs root (sudo) because the library talks to the NVMe drive directly.
"""
import ctypes
import fcntl
import hashlib
import hmac
import json
import os
from contextlib import contextmanager
from pathlib import Path

KAZ = 0x30
KAZ_PUBLIC_KEY_LENGTH = 118
KAZ_SIGNATURE_LENGTH = 354

ERRORS = {
    0: "P_SUCCESS", -1: "P_ERR_INVALID_BUFFER", -2: "P_ERR_MEMORY_ALLOCATION",
    -3: "P_ERR_CONVERSION_FAIL", -4: "P_ERR_DEVICE_CHECK_FAIL", -5: "P_ERR_SESSION_FAIL",
    -6: "P_ERR_SIGNATURE_FAIL", -7: "P_ERR_BUFFER_TOO_LARGE", -8: "P_ERR_VERIFY_FAIL",
    -9: "P_ERR_COMMAND_FAIL", -10: "P_ERR_CHECK_ALGORITHM_FAIL", -11: "P_ERR_GENERATE_KEY_PAIR_FAIL",
    -12: "P_ERR_SEND_SIGN_DATA_FAIL", -13: "P_ERR_SEND_VERIFY_DATA_FAIL",
    -14: "P_ERR_INVALID_SIGNATURE_LENGTH", -15: "P_ERR_INVALID_PUBLIC_KEY_LENGTH",
    -16: "P_ERR_GET_PUBLIC_KEY_FAIL", -17: "P_ERR_INVALID_KEY_SLOT",
    -18: "P_ERR_SEND_DOC_FAIL", -19: "P_ERR_GET_DOC_FAIL",
}
HINTS = {
    -4: "PQC_DEVICE in settings.py is not the Phison PQC SSD",
    -5: "wrong SSD password (PQC_PASSWORD in settings.py)",
    -9: "could not open the drive: run with sudo and check PQC_DEVICE",
    -16: "no key in that slot yet (run: sudo python3 edge_device.py register)",
}


class PQCError(Exception):
    def __init__(self, func, code):
        self.code = code
        hint = f" -> {HINTS[code]}" if code in HINTS else ""
        super().__init__(f"{func} failed with {code} ({ERRORS.get(code, 'UNKNOWN')}){hint}")


_BYTE_PTR = ctypes.POINTER(ctypes.c_ubyte)


class PhisonPQC:
    """Real hardware: Phison E31T PQC SSD."""
    name = "KAZ"

    def __init__(self, lib_path, device, password):
        if os.geteuid() != 0:
            raise SystemExit("The PQC SSD needs root. Run this script with: sudo python3 ...")
        if not Path(lib_path).exists():
            raise SystemExit(f"SDK library not found: {lib_path} (fix SDK_LIB in settings.py)")
        self.device = str(device).encode()
        self.password = bytes(password)
        self.lib = ctypes.CDLL(str(lib_path))
        # One lock file per drive, so edge_device.py and server.py never talk to
        # the same SSD at the same moment (the SDK is not thread/process safe).
        # /run is writable only by root, so a stray non-root run can never leave a
        # lock file there that blocks the real sudo run (as /run/lock would).
        self.lock_path = f"/run/phison-pqc-{Path(device).name}.lock"
        self._declare_functions()

    def _declare_functions(self):
        c_char_p, c_size_t, c_uint8, c_int = ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_int
        out_buf, out_len = ctypes.POINTER(_BYTE_PTR), ctypes.POINTER(c_size_t)
        signatures = {
            "is_phison_device": [c_char_p],
            "get_firmware_version": [c_char_p, c_char_p, c_size_t],
            "generate_key_pair": [c_char_p, c_char_p, c_size_t, out_buf, out_len, c_uint8, c_int, c_uint8],
            "get_public_key": [c_char_p, c_char_p, c_size_t, out_buf, out_len, c_uint8],
            "generate_signature": [c_char_p, c_char_p, c_size_t, c_char_p, c_size_t,
                                   out_buf, out_len, c_uint8, c_int, c_uint8],
            "verify_signature": [c_char_p, c_char_p, c_size_t, c_char_p, c_size_t,
                                 c_char_p, c_size_t, c_uint8],
            "verify_signature_with_key": [c_char_p, c_char_p, c_size_t, c_char_p, c_size_t,
                                          c_char_p, c_size_t, c_char_p, c_size_t, c_uint8, c_int, c_uint8],
        }
        for name, argtypes in signatures.items():
            func = getattr(self.lib, name)
            func.argtypes = argtypes
            func.restype = c_int
        self.lib.agent_free.argtypes = [ctypes.c_void_p]
        self.lib.agent_free.restype = None
        self.lib.get_agent_version.argtypes = []
        self.lib.get_agent_version.restype = ctypes.c_char_p

    @contextmanager
    def _locked(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the file also releases the lock

    def _take_buffer(self, func, code, ptr, length):
        """Copy a buffer allocated by the SDK, free it with agent_free, raise on error."""
        data = ctypes.string_at(ptr, length.value) if ptr else b""
        if ptr:
            self.lib.agent_free(ctypes.cast(ptr, ctypes.c_void_p))
        if code != 0:
            raise PQCError(func, code)
        return data

    def version(self):
        return self.lib.get_agent_version().decode()

    def check_device(self):
        """is_phison_device + get_firmware_version. Returns the firmware string."""
        with self._locked():
            code = self.lib.is_phison_device(self.device)
            if code != 0:
                raise PQCError("is_phison_device", code)
            fw = ctypes.create_string_buffer(18)
            code = self.lib.get_firmware_version(self.device, fw, len(fw))
        if code != 0:
            raise PQCError("get_firmware_version", code)
        return fw.value.decode(errors="replace")

    def generate_key_pair(self, slot):
        """Create a NEW key pair inside the SSD (overwrites the slot). Returns the public key."""
        ptr, length = _BYTE_PTR(), ctypes.c_size_t()
        with self._locked():
            code = self.lib.generate_key_pair(self.device, self.password, len(self.password),
                                              ctypes.byref(ptr), ctypes.byref(length), slot, KAZ, 0x01)
        return self._take_buffer("generate_key_pair", code, ptr, length)

    def get_public_key(self, slot):
        ptr, length = _BYTE_PTR(), ctypes.c_size_t()
        with self._locked():
            code = self.lib.get_public_key(self.device, self.password, len(self.password),
                                           ctypes.byref(ptr), ctypes.byref(length), slot)
        return self._take_buffer("get_public_key", code, ptr, length)

    def sign(self, data, slot):
        """Sign bytes with the private key in `slot` (force_flag=0: use existing key)."""
        ptr, length = _BYTE_PTR(), ctypes.c_size_t()
        with self._locked():
            code = self.lib.generate_signature(self.device, self.password, len(self.password),
                                               data, len(data), ctypes.byref(ptr), ctypes.byref(length),
                                               slot, KAZ, 0x00)
        return self._take_buffer("generate_signature", code, ptr, length)

    def verify(self, data, signature, slot):
        """Same-device verification with the key already in `slot`."""
        with self._locked():
            code = self.lib.verify_signature(self.device, self.password, len(self.password),
                                             data, len(data), signature, len(signature), slot)
        return self._verdict("verify_signature", code)

    def verify_with_key(self, data, signature, public_key, slot):
        """Cross-device verification: inject `public_key` into `slot`, then verify."""
        with self._locked():
            code = self.lib.verify_signature_with_key(self.device, self.password, len(self.password),
                                                      data, len(data), signature, len(signature),
                                                      public_key, len(public_key), slot, KAZ, 0x01)
        return self._verdict("verify_signature_with_key", code)

    @staticmethod
    def _verdict(func, code):
        if code == 0:
            return True
        if code == -8:  # P_ERR_VERIFY_FAIL = signature does not match the data
            return False
        raise PQCError(func, code)


class MockPQC:
    """Software stand-in so you can test audio + MQTT WITHOUT the SSD or sudo.
    NOT secure and NOT post-quantum: anyone with the public key can forge signatures.
    Never use it for the real demo."""
    name = "MOCK"

    def __init__(self, keystore):
        self.keystore = Path(keystore)

    def _load(self):
        return json.loads(self.keystore.read_text()) if self.keystore.exists() else {}

    @staticmethod
    def _fake_signature(public_key, data):
        return hashlib.shake_256(b"MOCK-KAZ" + public_key + data).digest(KAZ_SIGNATURE_LENGTH)

    def version(self):
        return "mock"

    def check_device(self):
        return "MOCK-FIRMWARE"

    def generate_key_pair(self, slot):
        keys = self._load()
        public_key = os.urandom(KAZ_PUBLIC_KEY_LENGTH)
        keys[str(slot)] = public_key.hex()
        self.keystore.write_text(json.dumps(keys))
        return public_key

    def get_public_key(self, slot):
        keys = self._load()
        if str(slot) not in keys:
            raise PQCError("get_public_key", -16)
        return bytes.fromhex(keys[str(slot)])

    def sign(self, data, slot):
        return self._fake_signature(self.get_public_key(slot), data)

    def verify(self, data, signature, slot):
        return hmac.compare_digest(self._fake_signature(self.get_public_key(slot), data), signature)

    def verify_with_key(self, data, signature, public_key, slot):
        return hmac.compare_digest(self._fake_signature(public_key, data), signature)


def open_pqc(mock=False):
    import settings
    if mock:
        print("\x1b[33m" + "!" * 70)
        print("!!  MOCK PQC MODE - no SSD, no real KAZ signatures. Testing only!  !!")
        print("!" * 70 + "\x1b[0m")
        return MockPQC(settings.MOCK_KEYSTORE)
    return PhisonPQC(settings.SDK_LIB, settings.PQC_DEVICE, settings.PQC_PASSWORD)
