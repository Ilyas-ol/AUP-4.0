Orchestrator Crate

Purpose
- Runs the 4 layout layers in sequence (TPM -> Enclave -> Kernel -> Detection)
- Produces a single decision payload without touching license or demo parts

Inputs
- Secret for TPM sealing
- Optional TPM blob for unseal
- Risk signal for routing
- Telemetry snapshot and honeypot flag

Outputs
- Execution route (real or decoy)
- Sealed blob when created
- Unsealed secret when provided
- Silent kill decision
