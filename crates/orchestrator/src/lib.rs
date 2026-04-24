use detection_layer::{DetectionError, DetectionLayer, TelemetrySnapshot};
use enclave_core::{Enclave, EnclaveError};
use kernel_bridge::{ExecutionRoute, KernelBridge, KernelBridgeError};
use tpm_binding::{TpmBinding, TpmBindingConfig, TpmError};

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
}

#[derive(Debug, Clone)]
pub struct OrchestratorInput {
    pub secret: Vec<u8>,
    pub tpm_blob: Option<Vec<u8>>,
    pub risk_signal: u8,
    pub telemetry: TelemetrySnapshot,
    pub honeypot_called: bool,
}

#[derive(Debug, Clone)]
pub struct OrchestratorResult {
    pub route: ExecutionRoute,
    pub sealed_blob: Option<Vec<u8>>,
    pub unsealed_secret: Option<Vec<u8>>,
    pub silent_kill: bool,
}

pub struct Orchestrator {
    tpm: TpmBinding,
    enclave: Enclave,
    kernel: KernelBridge,
    detection: DetectionLayer,
}

impl Orchestrator {
    pub fn new(require_tpm: bool, anomaly_threshold: u32) -> Self {
        let tpm = TpmBinding::new(TpmBindingConfig {
            require_tpm,
            machine_id_override: None,
        });
        Self {
            tpm,
            enclave: Enclave::new(),
            kernel: KernelBridge::new(),
            detection: DetectionLayer::new(anomaly_threshold),
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

        self.enclave.init()?;
        self.enclave.integrity_check()?;

        self.kernel.check_debugger()?;
        self.kernel.block_injection()?;
        self.kernel.detect_vm()?;
        let route = self.kernel.select_route(input.risk_signal);

        self.detection.check_honeypot(input.honeypot_called)?;
        self.detection.check_anomaly(&input.telemetry)?;
        let silent_kill = self.detection.should_silent_kill(&input.telemetry);

        Ok(OrchestratorResult {
            route,
            sealed_blob,
            unsealed_secret,
            silent_kill,
        })
    }
}
