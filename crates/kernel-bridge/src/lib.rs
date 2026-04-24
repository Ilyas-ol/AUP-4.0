#[derive(Debug, thiserror::Error)]
pub enum KernelBridgeError {
    #[error("debugger detected")]
    DebuggerDetected,
    #[error("injection detected")]
    InjectionDetected,
    #[error("vm or sandbox detected")]
    VmDetected,
    #[error("operation not implemented")]
    NotImplemented,
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutionRoute {
    RealPath,
    DecoyPath,
}

pub struct KernelBridge;

impl KernelBridge {
    pub fn new() -> Self {
        Self
    }

    pub fn check_debugger(&self) -> Result<(), KernelBridgeError> {
        if Self::env_flag("SIM_DEBUGGER") || Self::env_flag("DEBUGGER_PRESENT") {
            Err(KernelBridgeError::DebuggerDetected)
        } else {
            Ok(())
        }
    }

    pub fn block_injection(&self) -> Result<(), KernelBridgeError> {
        if Self::env_flag("SIM_INJECT") {
            Err(KernelBridgeError::InjectionDetected)
        } else {
            Ok(())
        }
    }

    pub fn detect_vm(&self) -> Result<(), KernelBridgeError> {
        if Self::env_flag("SIM_VM") {
            Err(KernelBridgeError::VmDetected)
        } else {
            Ok(())
        }
    }

    pub fn select_route(&self, risk_signal: u8) -> ExecutionRoute {
        let env_risk = if Self::env_flag("SIM_RISK") { 1 } else { 0 };
        if risk_signal == 0 && env_risk == 0 {
            ExecutionRoute::RealPath
        } else {
            ExecutionRoute::DecoyPath
        }
    }

    fn env_flag(key: &str) -> bool {
        std::env::var(key).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
    }
}
