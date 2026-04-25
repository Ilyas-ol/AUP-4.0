# AUP 4-Layer Offline License Protection - Pitch Summary

## One-Line Pitch
AUP protects offline software licenses with a 4-layer architecture that blocks tampering, prevents replay on other machines, and provides tamper evidence without requiring any internet access.

## The Problem
On-prem and offline software licenses are easy to copy, patch, or bypass. Standard online verification is not an option in air-gapped or restricted environments.

## The Solution
We combine four independent layers so breaking one does not break the system:
1) TPM hardware binding (Layer 0)
2) Trusted execution for secret handling (Layer 1)
3) Kernel-level anti-tamper controls (Layer 2)
4) Detection and deception with local telemetry (Layer 3)

## Why It Works
- Machine binding stops license replay on other devices.
- Trusted execution protects keys and validation logic from memory inspection.
- Kernel controls block debugger attach, injection, and sandbox analysis.
- Detection layer logs tamper attempts and enables silent/slow kill responses.

## Offline by Design
All checks are local and work without internet. Telemetry is stored locally and can be exported later if needed.

## Integration Model
- Rust core provides the security logic.
- A native FFI library exposes stable functions.
- Thin SDKs (Node, Python) let clients integrate in any language.

## Demo Highlights
- Valid license passes.
- Modified license fails signature check.
- Replay on another machine fails TPM binding.
- Debugger/injection/VM flags deny execution.
- Honeypot triggers tamper evidence.

## What is Simulated in the Demo
- TPM, enclave, and kernel checks are simulated for rapid testing.
- The control flow is production-aligned and can be swapped with real components.

## Roadmap to Full Production
- Replace TPM mock with TPM 2.0 APIs.
- Use real enclave (SGX/SEV/TrustZone).
- Ship signed kernel driver for Windows.
- Harden telemetry and anti-patch checks.

## Why Judges Should Care
- Realistic for offline customers.
- Layered defense is credible and extensible.
- Simple SDK integration for enterprise clients.
