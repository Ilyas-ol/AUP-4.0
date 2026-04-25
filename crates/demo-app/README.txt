Demo App

Usage
- demo-app <license.json> <public_key.txt> <runtime_input.json>

Runtime Input JSON
- requested_users (u32)
- requested_modules (array of strings)
- machine_binding (string or null)
- risk_signal (u8)
- honeypot_called (bool)
- telemetry.active_users (u32)
- telemetry.module_switches (u32)
- telemetry.request_rate (u32)

System Behavior
- Uses current UTC date from system clock for license date checks
- Writes encrypted telemetry to telemetry.json

Notes
- Uses production-style runtime input (no demo env toggles)
