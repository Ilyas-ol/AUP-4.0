# Demo Q&A (Simulation)

## Why simulation?
- Hardware layers cannot be assumed on every laptop.
- Control flow is identical to production.

## Is it credible?
- Real signature verification and constraints are used.
- Real encrypted telemetry is used.
- Only hardware hooks are stubbed.

## What changes in production?
- Swap simulated TPM/enclave/driver with real implementations.
- Keep orchestrator and SDKs unchanged.
