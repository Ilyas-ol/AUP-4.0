# AUP Node SDK (FFI)

Purpose
- Thin Node wrapper over the AUP native library.

Prereqs
- Build the Rust FFI library: `crates/sdk-ffi`.
- Provide the library path via `AUP_SDK_LIB` or place the DLL next to the app.

Usage
- Call `verifyLicenseJson` with `licenseJson`, `publicKeyB64`, `today`, `requestedUsers`, `requestedModulesCsv`, `machineBinding`.

Notes
- This is scaffolding. You can expand errors and add async wrappers later.
