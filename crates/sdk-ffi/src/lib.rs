use license_verifier::{validate_constraints, verify_from_str, LicenseConstraints, VerifyError};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

const SDK_OK: i32 = 0;
const SDK_INVALID_LICENSE: i32 = 1;
const SDK_CONSTRAINT_FAILED: i32 = 2;
const SDK_INTERNAL_ERROR: i32 = 3;

fn set_last_error(message: impl Into<String>) {
    let mut guard = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(message.into());
}

fn clear_last_error() {
    let mut guard = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn cstr_to_string(ptr: *const c_char) -> Result<String, &'static str> {
    if ptr.is_null() {
        return Err("null pointer");
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().map(|s| s.to_string()).map_err(|_| "invalid utf-8")
}

fn optional_cstr(ptr: *const c_char) -> Result<Option<String>, &'static str> {
    if ptr.is_null() {
        return Ok(None);
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let value = cstr.to_str().map_err(|_| "invalid utf-8")?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

#[no_mangle]
pub extern "C" fn sdk_verify_license_json(
    license_json: *const c_char,
    public_key_b64: *const c_char,
    today: *const c_char,
    requested_users: u32,
    requested_modules_csv: *const c_char,
    machine_binding: *const c_char,
) -> i32 {
    clear_last_error();

    let license_json = match cstr_to_string(license_json) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err);
            return SDK_INTERNAL_ERROR;
        }
    };

    let public_key_b64 = match cstr_to_string(public_key_b64) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err);
            return SDK_INTERNAL_ERROR;
        }
    };

    let today = match cstr_to_string(today) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err);
            return SDK_INTERNAL_ERROR;
        }
    };

    let modules_csv = match optional_cstr(requested_modules_csv) {
        Ok(value) => value.unwrap_or_default(),
        Err(err) => {
            set_last_error(err);
            return SDK_INTERNAL_ERROR;
        }
    };

    let requested_modules = if modules_csv.is_empty() {
        Vec::new()
    } else {
        modules_csv
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    };

    let machine_binding = match optional_cstr(machine_binding) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err);
            return SDK_INTERNAL_ERROR;
        }
    };

    let payload = match verify_from_str(&license_json, &public_key_b64) {
        Ok(value) => value,
        Err(err) => {
            set_last_error(format!("license verify failed: {err}"));
            return SDK_INVALID_LICENSE;
        }
    };

    let constraints = LicenseConstraints {
        today,
        requested_users,
        requested_modules,
        machine_binding,
    };

    match validate_constraints(&payload, &constraints) {
        Ok(()) => SDK_OK,
        Err(VerifyError::ConstraintFailed) => {
            set_last_error("constraint failed");
            SDK_CONSTRAINT_FAILED
        }
        Err(err) => {
            set_last_error(format!("constraint error: {err}"));
            SDK_INTERNAL_ERROR
        }
    }
}

#[no_mangle]
pub extern "C" fn sdk_last_error(buf: *mut c_char, buf_len: usize) -> usize {
    let guard = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    let message = match guard.as_ref() {
        Some(value) => value,
        None => "",
    };

    let cstring = match CString::new(message) {
        Ok(value) => value,
        Err(_) => return 0,
    };

    let bytes = cstring.as_bytes_with_nul();
    let required = bytes.len();
    if buf.is_null() || buf_len == 0 {
        return required;
    }

    let copy_len = if buf_len < required { buf_len } else { required };
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy_len);
    }

    required
}
