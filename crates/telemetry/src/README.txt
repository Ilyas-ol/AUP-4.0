Telemetry Crate

Purpose
- Encrypted local log buffer for offline environments
- Optional upload via caller-provided callback

Notes
- Uses AES-256-GCM with a caller-provided 32-byte key
- Stores encrypted events in a JSON file
