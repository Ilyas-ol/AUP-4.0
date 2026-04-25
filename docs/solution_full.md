# AUP 4-Layer Offline License Protection - Full Solution Explanation

## 1) Executive Summary
This solution protects an on-prem/offline software license using a layered defense model. It combines:
- hardware-bound secrets,
- trusted execution for sensitive logic,
- kernel-level hardening,
- detection and deception for tamper evidence.

Even if one layer is bypassed, the remaining layers continue to protect the system. The implementation is built as a Rust workspace, with a demo harness and SDK scaffolding for Node and Python (FFI).

## 2) Goals and Constraints
### Goals
- Prevent license tampering and replay on other machines.
- Protect secrets and validation logic.
- Detect bypass attempts and generate evidence.
- Operate fully offline.

### Constraints
- Must run in restricted, air-gapped, or low-connectivity environments.
- Prefer commodity hardware where possible.
- Provide a realistic path from demo to production.

## 3) Architecture Overview
### 4-Layer Security Stack
- Layer 0 (TPM Root of Trust): hardware-bound secrets via seal/unseal.
- Layer 1 (Trusted Execution): isolate key handling and validation logic.
- Layer 2 (Kernel Control): block debugger, injection, and sandbox/VM.
- Layer 3 (Detection + Deception): honeypots, anomaly rules, tamper logging.

### Cross-Layer Flow
1) Load license and verify signature.
2) Unseal machine-bound secret (TPM).
3) Execute sensitive logic in a trusted boundary (enclave).
4) Enforce runtime integrity checks (kernel layer).
5) Detect and log suspicious behavior (detection layer).
6) Allow or deny execution.

## 4) License Model and Cryptography
### License Payload
Key fields:
- license_id, customer_id, product_id
- modules[]
- max_users
- valid_from, valid_to
- environment_type
- machine_binding
- binary_hash
- issued_at, version

### Signature
- Payload is signed by the issuer using Ed25519.
- Application embeds the public key and verifies signatures offline.

### Optional Confidentiality
- Sensitive fields can be encrypted and only decrypted after TPM release.

## 5) Layer Details (Simulation vs Production)
### Layer 0: TPM (Root of Trust)
Purpose: bind license secrets to a machine and boot integrity.

Detailed steps:
1) Installation time: generate a random secret.
2) Seal secret to TPM PCR values (boot state).
3) Runtime: unseal secret only if PCR values match.
4) If unseal fails, deny execution.

Simulation (current):
- Uses machine identity + SHA-256 to simulate seal/unseal.
- Fails if machine binding does not match.

Production (future):
- Use TPM 2.0 APIs to seal secrets to PCR values.
- Unseal only if boot state matches.

### Layer 1: Enclave (Trusted Execution)
Purpose: protect key handling and license validation from OS inspection.

Detailed steps:
1) Create enclave and verify its measurement.
2) Move license validation logic inside enclave.
3) Provide only minimal outputs (valid/invalid) to host.
4) Wipe sensitive memory after use.

Simulation (current):
- Enclave init/integrity check is stubbed.

Production (future):
- Real enclave (SGX/SEV/TrustZone) holds validation logic.
- Only returns VALID or INVALID to host.

### Layer 2: Kernel / Driver Control
Purpose: prevent bypass via debugger, injection, or sandbox.

Detailed steps:
1) Register callbacks for process and module load.
2) Block unsigned or unexpected module loads.
3) Detect debugger attachment.
4) Detect VM/sandbox signals.
5) Route to real or decoy path based on risk.

Simulation (current):
- Env flags simulate debugger/injection/VM detection.

Production (future):
- Signed kernel driver with process/module callbacks.
- Blocks debugger attach, unsigned DLL injection, VM signatures.

### Layer 3: Detection + Deception
Purpose: detect tampering, log evidence, and waste attacker time.

Detailed steps:
1) Trigger honeypot if a decoy path is accessed.
2) Evaluate telemetry against anomaly rules.
3) Write encrypted event logs locally.
4) Optionally return silent-kill or degrade signals.

Simulation (current):
- Honeypot and anomaly rules.
- Encrypted local telemetry buffer.

Production (future):
- Tamper-evident logs, offline export.
- Slow-kill / degrade responses.

## 6) Core Components in the Workspace
### license-core
- License structs, key generation, sign/verify.

### license-issuer
- CLI to generate keys and issue licenses.

### license-verifier
- Verifies signed license and enforces constraints.

### tpm-binding
- Simulated TPM seal/unseal logic.

### enclave-core
- Simulated enclave boundary.

### kernel-bridge
- Simulated debugger/injection/VM checks.

### detection-layer
- Honeypot detection and anomaly rules.

### telemetry
- AES-GCM encrypted local event log.

### orchestrator
- Wires all layers and produces a single allow/deny decision.

### demo-app
- Test harness for running and simulating attacks.

## 7) Orchestrator Workflow (Runtime)
1) Verify license signature (license-verifier).
2) Validate constraints (date, modules, user count, machine binding).
3) Seal or unseal secret via TPM binding.
4) Initialize enclave and run integrity check.
5) Run kernel checks (debugger, injection, VM).
6) Run detection layer (honeypot + anomaly).
7) Produce route (real or decoy) and final decision.

### Orchestrator Decision Matrix
- License invalid -> deny
- Constraint failed -> deny
- TPM unseal failed -> deny
- Enclave integrity failed -> deny
- Debugger/injection/VM detected -> deny or decoy
- Honeypot triggered -> deny + log
- Anomaly exceeded -> deny or silent kill

## 8) SDK Strategy (Node + Python)
### Why SDKs
- Allow clients to integrate without caring about language/runtime.
- Keep the security logic in one Rust core.

### FFI Model (Current)
- Rust core is compiled as a native library.
- A stable C ABI is exposed via `sdk-ffi`.
- Node and Python SDKs are thin wrappers over the C ABI.

### SDK Call Flow (Detailed)
1) Client app calls SDK verify function.
2) SDK loads native library and marshals inputs.
3) Native library validates license and constraints.
4) Native returns status code and error details.
5) SDK maps errors to client-friendly results.

### Current FFI API
- `sdk_verify_license_json(...)` returns status code.
- `sdk_last_error(...)` returns last error message.

### What Clients Do
- Install SDK package.
- Place the native library next to their app.
- Call the SDK verification function at startup or feature-gate.

### Benefits
- Offline by design.
- Same validation behavior across languages.
- No reimplementation of security logic.

## 9) Demo Scenarios (Attack and Defense)
### Valid run
- Signed license matches constraints.
- App starts normally.

### Tamper attempt
- Modify license data.
- Signature check fails.

### Replay on another machine
- Machine binding fails.

### Debugger attach
- Kernel layer detects and blocks.

### Honeypot trigger
- Detection layer logs event and denies.

### Anomaly spike
- Silent kill or deny based on thresholds.


## 10) Offline Assurance
- No network calls required.
- All checks are local.
- Telemetry remains local unless exported intentionally.

## 11) Roadmap to Full Production
1) Replace simulated TPM with real TPM 2.0 integration.
2) Replace enclave stub with actual SGX/SEV/TrustZone.
3) Implement signed kernel driver for Windows.
4) Add anti-patch checks in multiple code paths.
5) Harden telemetry with tamper-evident storage.
6) Expand SDK API to expose full orchestrator pipeline.

## 12) Pitch Narrative (Short Version)
- Our system uses a 4-layer architecture so no single bypass works.
- TPM ties the license to the machine.
- Trusted execution hides secrets.
- Kernel controls prevent patching and debugging.
- Detection layer provides tamper evidence.
- The solution stays offline and integrates via SDKs in any language.

## 13) Appendix: How to Generate a License (Demo)
1) Generate keys:
   cargo run -p license-issuer -- gen-keys --out-private licenses\keys\private.key --out-public licenses\keys\public.key
2) Create payload JSON.
3) Sign payload:
   cargo run -p license-issuer -- issue --payload licenses\payload.json --private-key licenses\keys\private.key --out licenses\license.signed.json

## 14) Appendix: How to Run the Demo
- Normal run:
   cargo run -p demo-app -- licenses\license.signed.json licenses\keys\public.key licenses\runtime_input.normal.json
- Runtime input:
   Provide runtime context in JSON (requested users/modules, machine binding, risk signal, honeypot flag, telemetry snapshot).
