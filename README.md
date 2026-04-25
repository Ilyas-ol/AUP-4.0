# AUP-4.0: 4-Layer Offline License Protection

**AUP-4.0** is an offline, on-prem software license protection system designed to prevent tampering, falsification, and bypass. It is built entirely in Rust and utilizes a 4-layer defense architecture to make cracking economically irrational.

## 👨‍⚖️ Note to Judges: How to Evaluate This Project

If you are a judge looking to evaluate this codebase quickly, we have provided two automated, interactive scripts that will walk you through the entire 4-layer defense architecture, demonstrating both valid runs and thwarted attacks in real-time.

**To run the interactive test suite locally (Requires Rust):**
```powershell
.\scripts\judge_demo.ps1
```

**To run the interactive test suite via Docker:**
```powershell
.\scripts\judge_docker_demo.ps1
```

*(These scripts will guide you step-by-step through generating keys, issuing AES-encrypted licenses, and simulating Tampering, Rollbacks, and Honeypot triggers).*

---

## 🛡 Architecture

AUP-4.0 protects licenses across four independent layers. Even if an attacker bypasses one layer, the remaining layers continue to protect the system.

1. **Layer 0 (TPM Root of Trust)**: Binds the license secret to the physical machine using TPM 2.0 (sealing/unsealing based on platform configuration).
2. **Layer 1 (Trusted Execution Enclave)**: Executes the sensitive license validation and cryptographic decryption inside an isolated enclave, protecting secrets from memory dumps and debuggers.
3. **Layer 2 (Kernel / Control Flow)**: Prevents trivial patching or debugging by detecting debug ports, scanning for unauthorized DLL injection, and verifying virtual machine signatures.
4. **Layer 3 (Detection & Deception)**: Uses honeypots and lightweight anomaly detection to capture tamper attempts and generate encrypted forensic evidence.

## ⚔ Threat Model & Mitigations

| Threat | Mitigation Layer | Mechanism |
|--------|------------------|-----------|
| **Replay on another machine** | Layer 0 (TPM) | Hardware fingerprinting and TPM sealing prevent the secret from unsealing elsewhere. |
| **Reverse engineering secrets** | Layer 1 (Enclave) | AES-256-GCM encryption keeps the payload encrypted in transit. It is only unsealed and verified inside the trusted execution boundary. |
| **Binary patching (NOP bypass)** | Anti-Tamper | SHA-256 hash of the application executable is compared at runtime against the signed hash within the license payload. |
| **Debugger / DLL Injection** | Layer 2 (Kernel) | Checks for active debuggers and unauthorized injected modules. |
| **License Rollback** | Orchestrator | Persistent state tracks the latest license version and issue date to reject older replayed licenses. |

## 🚀 Quickstart

AUP-4.0 is structured as a Rust workspace containing the core libraries, CLI issuer, orchestrator, and a demo app.

### 1. Generate Keys

```powershell
cargo run -p license-issuer -- gen-keys --out-private licenses\keys\private.key --out-public licenses\keys\public.key
```

### 2. Issue an Encrypted License

```powershell
cargo run -p license-issuer -- issue `
    --payload licenses\payload.json `
    --private-key licenses\keys\private.key `
    --out licenses\license.signed.json `
    --encryption-key "demo-secret-32-byte-key-padding!"
```

### 3. Run the Demo App

The demo app loads the license, initializes the 4-layer orchestrator, and evaluates the simulated environment variables.

```powershell
cargo run -p demo-app -- licenses\license.signed.json licenses\keys\public.key licenses\runtime_input.normal.json
```

## 🐳 Docker Deployment

AUP-4.0 is fully dockerized to allow testing in isolated environments. The containerized build automatically falls back to cross-platform simulators for the Kernel/TPM layers while preserving the full validation logic.

### Start the application
```powershell
docker-compose up demo-app --build
```

### Issue a new license via Docker
```powershell
docker-compose run issue-license
```



## 📦 SDKs

To allow integration into different tech stacks without rewriting the security logic, the core engine exports a stable C-ABI (`sdk-ffi`). We provide bindings for:

- **Node.js** (`sdk/node`)
- **Python** (`sdk/python`)

## ⚠️ Limitations & Future Work

- **Enclave Simulation:** Currently, Layer 1 simulates the enclave boundary. A production deployment requires integration with actual SGX / SEV SDKs.
- **Kernel Driver:** Currently, Layer 2 uses Win32 user-mode API checks. A production deployment should use a signed kernel-mode driver (WDK).
- **Canary Tokens:** The schema can be expanded to embed watermarks and canary tokens for offline distribution tracking.
- **Distributed Verification:** Instead of checking the license at a single point, verification calls should be distributed across multiple code paths to complicate binary patching.
