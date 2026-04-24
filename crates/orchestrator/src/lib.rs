use detection_layer::{DetectionError, DetectionLayer, TelemetrySnapshot};
use enclave_core::{Enclave, EnclaveError};
use kernel_bridge::{ExecutionRoute, KernelBridge, KernelBridgeError};
use license_verifier::{validate_constraints, verify_from_str, LicenseConstraints, VerifyError};
use telemetry::{TelemetryEvent, TelemetryStore};
use tpm_binding::{TpmBinding, TpmBindingConfig, TpmError};
use std::path::PathBuf;

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
    #[error("telemetry error")]
    Telemetry,
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
}

pub struct Orchestrator {
    tpm: TpmBinding,
    enclave: Enclave,
    kernel: KernelBridge,
    detection: DetectionLayer,
    telemetry: TelemetryStore,
}

impl Orchestrator {
    pub fn new(config: OrchestratorConfig) -> Self {
        let tpm = TpmBinding::new(TpmBindingConfig {
            require_tpm: config.require_tpm,
            machine_id_override: None,
        });
        Self {
            tpm,
            enclave: Enclave::new(),
            kernel: KernelBridge::new(),
            detection: DetectionLayer::new(config.anomaly_threshold),
            telemetry: TelemetryStore::new(config.telemetry_path, config.telemetry_key),
        }
    }

    pub fn run(&mut self, input: OrchestratorInput) -> Result<OrchestratorResult, OrchestratorError> {
        self.tpm.require_available()?;

        let payload = verify_from_str(&input.license_data, &input.license_public_key_b64)?;
        validate_constraints(&payload, &input.license_constraints)?;

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

        self.enclave.init()?;
        self.enclave.integrity_check()?;

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
