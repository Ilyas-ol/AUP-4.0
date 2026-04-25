# AUP Python SDK (FFI)

Purpose
- Thin Python wrapper over the AUP native library.

Prereqs
- Build the Rust FFI library: `crates/sdk-ffi`.
- Provide the library path via `AUP_SDK_LIB` or place the DLL next to the app.

Usage
- Call `verify_license_json` with `license_json`, `public_key_b64`, `today`, `requested_users`, `requested_modules_csv`, `machine_binding`.

Notes
- This is scaffolding. You can add richer exceptions and logging later.
