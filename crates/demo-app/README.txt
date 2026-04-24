Demo App

Usage
- demo-app <license.json> <public_key.txt>

Environment Variables
- REQ_USERS (default: 1)
- REQ_MODULES (comma-separated, default: core)
- TODAY (default: 2026-06-01)
- MACHINE_BINDING (optional)
- RISK_SIGNAL (default: 0)
- HONEYPOT (true/1 to trigger)
- TELEMETRY_PATH (default: telemetry.json)

Notes
- Uses simulated layers and orchestrator flow
- Writes encrypted telemetry when honeypot or anomaly triggers
