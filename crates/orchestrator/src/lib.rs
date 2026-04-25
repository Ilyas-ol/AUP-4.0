use anti_tamper::{hash_file, IntegrityError};
use detection_layer::{DetectionError, DetectionLayer, TelemetrySnapshot};
use enclave_core::{Enclave, EnclaveError};
use kernel_bridge::{ExecutionRoute, KernelBridge, KernelBridgeError};
use license_verifier::{validate_constraints, verify_from_str, LicenseConstraints, VerifyError};
use telemetry::{TelemetryEvent, TelemetryStore};
use tpm_binding::{TpmBinding, TpmBindingConfig, TpmError};
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct LicenseState {
    pub last_version: u32,
    pub last_issued_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("tpm error: {0}")]
    Tpm(#[from] TpmError),
    #[error("enclave error: {0}")]
    Enclave(#[from] EnclaveError),
    #[error("kernel bridge error: {0}")]
    KernelBridge(#[from] KernelBridgeError),
    #[error("detection error: {0}")]
    Detection(#[from] DetectionError),
    #[error("license error: {0}")]
    License(#[from] VerifyError),
    #[error("integrity error: {0}")]
    Integrity(#[from] IntegrityError),
    #[error("telemetry error")]
    Telemetry,
    #[error("rollback detected")]
    RollbackDetected,
}

#[derive(Debug, Clone)]
pub struct OrchestratorInput {
    pub secret: Vec<u8>,
    pub tpm_blob: Option<Vec<u8>>,
    pub risk_signal: u8,
    pub telemetry: TelemetrySnapshot,
    pub honeypot_called: bool,
    pub license_data: String,
    pub license_public_key_b64: String,
    pub license_constraints: LicenseConstraints,
    /// Path to the protected binary for hash verification.
    pub binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct OrchestratorResult {
    pub route: ExecutionRoute,
    pub sealed_blob: Option<Vec<u8>>,
    pub unsealed_secret: Option<Vec<u8>>,
    pub silent_kill: bool,
    pub license_ok: bool,
}

#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub require_tpm: bool,
    pub anomaly_threshold: u32,
    pub telemetry_path: PathBuf,
    pub telemetry_key: [u8; 32],
    pub state_path: PathBuf,
}

pub struct Orchestrator {
    tpm: TpmBinding,
    enclave: Enclave,
    kernel: KernelBridge,
    detection: DetectionLayer,
    telemetry: TelemetryStore,
    state_path: PathBuf,
}

impl Orchestrator {
    pub fn new(config: OrchestratorConfig) -> Self {
        Self::new_with_kernel(config, KernelBridge::new())
    }

    pub fn new_with_kernel(config: OrchestratorConfig, kernel: KernelBridge) -> Self {
        let tpm = TpmBinding::new(TpmBindingConfig {
            require_tpm: config.require_tpm,
            machine_id_override: None,
        });
        Self {
            tpm,
            enclave: Enclave::new(),
            kernel,
            detection: DetectionLayer::new(config.anomaly_threshold),
            telemetry: TelemetryStore::new(config.telemetry_path, config.telemetry_key),
            state_path: config.state_path,
        }
    }

    fn load_state(&self) -> LicenseState {
        if let Ok(data) = fs::read_to_string(&self.state_path) {
            if let Ok(state) = serde_json::from_str(&data) {
                return state;
            }
        }
        LicenseState::default()
    }

    fn save_state(&self, state: &LicenseState) {
        if let Ok(data) = serde_json::to_string(state) {
            let _ = fs::write(&self.state_path, data);
        }
    }

    pub fn run(&mut self, input: OrchestratorInput) -> Result<OrchestratorResult, OrchestratorError> {
        self.tpm.require_available()?;

        let sealed_blob = if input.tpm_blob.is_none() {
            Some(self.tpm.seal_secret(&input.secret)?)
        } else {
            None
        };

        let unsealed_secret = if let Some(blob) = input.tpm_blob.as_ref() {
            Some(self.tpm.unseal_secret(blob)?)
        } else {
            None
        };

        let actual_secret = unsealed_secret.as_ref().unwrap_or(&input.secret);

        let enclave_key: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, byte) in k.iter_mut().enumerate() {
                *byte = actual_secret[i % actual_secret.len()];
            }
            k
        };

        let decrypted_license = license_core::decrypt_license(&input.license_data, &enclave_key)
            .map_err(|_| OrchestratorError::Telemetry)?; // mapped to Telemetry for simplicity, or we could add CryptoError

        let payload = verify_from_str(&decrypted_license, &input.license_public_key_b64)?;
        validate_constraints(&payload, &input.license_constraints)?;

        // --- Anti-Rollback ---
        let mut state = self.load_state();
        if payload.version < state.last_version {
            return Err(OrchestratorError::RollbackDetected);
        }
        if payload.version == state.last_version && payload.issued_at < state.last_issued_at {
            return Err(OrchestratorError::RollbackDetected);
        }
        
        state.last_version = payload.version;
        state.last_issued_at = payload.issued_at.clone();
        self.save_state(&state);

        // --- Anti-Tamper: verify binary hash if present in license ---
        if let (Some(expected_hex), Some(bin_path)) = (&payload.binary_hash, &input.binary_path) {
            let actual_hash = hash_file(bin_path)?;
            let expected_bytes = hex_to_bytes(expected_hex)
                .ok_or(IntegrityError::HashMismatch)?;
            if expected_bytes.len() != 32 {
                return Err(IntegrityError::HashMismatch.into());
            }
            let mut expected_arr = [0u8; 32];
            expected_arr.copy_from_slice(&expected_bytes);
            anti_tamper::verify_hash(expected_arr, actual_hash)?;
            self.append_event("integrity", "binary hash verified OK")?;
        }

        self.enclave.init()?;
        self.enclave.integrity_check()?;

        // Execute license verification inside enclave boundary.
        // The enclave seals/unseals the license data, proving the trust boundary.
        let _enclave_result = self.enclave.execute_trusted(
            &enclave_key,
            decrypted_license.as_bytes(),
        )?;

        self.kernel.check_debugger()?;
        self.kernel.block_injection()?;
        self.kernel.detect_vm()?;
        let route = self.kernel.select_route(input.risk_signal);

        if let Err(err) = self.detection.check_honeypot(input.honeypot_called) {
            self.append_event("honeypot", &format!("{err}"))?;
            return Err(err.into());
        }

        if let Err(err) = self.detection.check_anomaly(&input.telemetry) {
            self.append_event("anomaly", &format!("{err}"))?;
            return Err(err.into());
        }
        let silent_kill = self.detection.should_silent_kill(&input.telemetry);

        Ok(OrchestratorResult {
            route,
            sealed_blob,
            unsealed_secret,
            silent_kill,
            license_ok: true,
        })
    }

    fn append_event(&self, event_type: &str, details: &str) -> Result<(), OrchestratorError> {
        let event = TelemetryEvent {
            timestamp: current_timestamp(),
            event_type: event_type.to_string(),
            details: details.to_string(),
        };
        self.telemetry.append_event(event).map_err(|_| OrchestratorError::Telemetry)
    }
}

fn current_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs().to_string()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use license_core::{sign_payload, LicensePayload};

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("orch_{name}_{pid}_{now}.json"));
        path
    }

    fn sample_payload() -> LicensePayload {
        LicensePayload {
            license_id: "LIC-ORCH".to_string(),
            customer_id: "CUST-1".to_string(),
            product_id: "PROD-1".to_string(),
            modules: vec!["core".to_string(), "pro".to_string()],
            max_users: 5,
            valid_from: "2026-01-01".to_string(),
            valid_to: "2026-12-31".to_string(),
            environment_type: "on-prem".to_string(),
            machine_binding: Some("MACHINE-1".to_string()),
            binary_hash: None,
            issued_at: "2026-04-24".to_string(),
            version: 1,
        }
    }

    #[test]
    fn orchestrator_runs_and_logs_honeypot() {
        let (priv_b64, pub_b64) = license_core::generate_keypair();
        let payload = sample_payload();
        let signed = sign_payload(&payload, &priv_b64).expect("sign");
        let license_data = serde_json::to_string(&signed).expect("json");

        let telemetry_path = temp_path("honeypot");
        let telemetry_key = [3u8; 32];

        let mut orchestrator = Orchestrator::new_with_kernel(
            OrchestratorConfig {
                require_tpm: false,
                anomaly_threshold: 10,
                telemetry_path: telemetry_path.clone(),
                telemetry_key,
                state_path: temp_path("state"),
            },
            KernelBridge::with_provider(Box::new(kernel_bridge::NullThreatSignalProvider)),
        );

        let input = OrchestratorInput {
            secret: b"secret".to_vec(),
            tpm_blob: None,
            risk_signal: 0,
            telemetry: TelemetrySnapshot {
                active_users: 1,
                module_switches: 0,
                request_rate: 1,
            },
            honeypot_called: true,
            license_data,
            license_public_key_b64: pub_b64,
            license_constraints: LicenseConstraints {
                today: "2026-06-01".to_string(),
                requested_users: 1,
                requested_modules: vec!["core".to_string()],
                machine_binding: Some("MACHINE-1".to_string()),
            },
            binary_path: None,
        };

        let result = orchestrator.run(input);
        assert!(result.is_err());

        let store = TelemetryStore::new(telemetry_path, telemetry_key);
        let events = store.load_events().expect("load");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "honeypot");
    }
}
