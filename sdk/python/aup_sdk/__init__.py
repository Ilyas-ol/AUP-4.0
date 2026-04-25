import ctypes
import os

SDK_OK = 0
SDK_INVALID_LICENSE = 1
SDK_CONSTRAINT_FAILED = 2
SDK_INTERNAL_ERROR = 3

_lib_path = os.environ.get("AUP_SDK_LIB", "./aup_sdk.dll")
_lib = ctypes.CDLL(_lib_path)

_lib.sdk_verify_license_json.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.sdk_verify_license_json.restype = ctypes.c_int

_lib.sdk_last_error.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
_lib.sdk_last_error.restype = ctypes.c_size_t


def _last_error() -> str:
    size = _lib.sdk_last_error(None, 0)
    if size == 0:
        return ""
    buf = ctypes.create_string_buffer(size)
    _lib.sdk_last_error(buf, size)
    return buf.value.decode("utf-8", errors="ignore")


def verify_license_json(
    license_json: str,
    public_key_b64: str,
    today: str,
    requested_users: int = 0,
    requested_modules_csv: str = "",
    machine_binding: str = "",
):
    result = _lib.sdk_verify_license_json(
        license_json.encode("utf-8"),
        public_key_b64.encode("utf-8"),
        today.encode("utf-8"),
        int(requested_users),
        requested_modules_csv.encode("utf-8"),
        machine_binding.encode("utf-8"),
    )
    return {
        "code": result,
        "error": "" if result == SDK_OK else _last_error(),
    }
