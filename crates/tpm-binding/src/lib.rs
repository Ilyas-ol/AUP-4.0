#[cfg(all(feature = "real-tpm", target_os = "windows"))]
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use std::process::Command;

pub struct TpmBindingConfig {
    pub require_tpm: bool,
    pub machine_id_override: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("tpm not available")]
    NotAvailable,
    #[error("unseal failed")]
    UnsealFailed,
    #[error("invalid blob")]
    InvalidBlob,
    #[error("operation not implemented")]
    NotImplemented,
    #[error("platform operation failed")]
    PlatformFailure,
}

pub struct TpmBinding {
    config: TpmBindingConfig,
}

impl TpmBinding {
    pub fn new(config: TpmBindingConfig) -> Self {
        Self { config }
    }

    pub fn is_available(&self) -> bool {
        #[cfg(all(feature = "real-tpm", target_os = "windows"))]
        {
            if self.config.require_tpm {
                return real_tpm_ready_windows();
            }
        }

        // Fallback availability uses host identity collection.
        self.machine_id().is_some()
    }

    pub fn seal_secret(&self, _secret: &[u8]) -> Result<Vec<u8>, TpmError> {
        #[cfg(all(feature = "real-tpm", target_os = "windows"))]
        if self.config.require_tpm {
            return self.seal_secret_real(_secret);
        }

        let machine_id = self.machine_id().ok_or(TpmError::NotAvailable)?;
        let mut machine_hash = Sha256::new();
        machine_hash.update(machine_id.as_bytes());
        let machine_hash = machine_hash.finalize();

        let key = Self::derive_key(&machine_hash);
        let mut sealed = Vec::new();

        sealed.extend_from_slice(b"TPMS");
        sealed.extend_from_slice(&machine_hash);
        sealed.extend_from_slice(&( _secret.len() as u32).to_le_bytes());

        let mut obfuscated = Vec::with_capacity(_secret.len());
        for (idx, byte) in _secret.iter().enumerate() {
            obfuscated.push(byte ^ key[idx % key.len()]);
        }
        sealed.extend_from_slice(&obfuscated);

        let checksum = Self::checksum(&sealed);
        sealed.extend_from_slice(&checksum);
        Ok(sealed)
    }

    pub fn unseal_secret(&self, _blob: &[u8]) -> Result<Vec<u8>, TpmError> {
        #[cfg(all(feature = "real-tpm", target_os = "windows"))]
        if self.config.require_tpm {
            return self.unseal_secret_real(_blob);
        }

        if _blob.len() < 4 + 32 + 4 + 32 {
            return Err(TpmError::InvalidBlob);
        }
        if &_blob[0..4] != b"TPMS" {
            return Err(TpmError::InvalidBlob);
        }

        let machine_id = self.machine_id().ok_or(TpmError::NotAvailable)?;
        let mut machine_hash = Sha256::new();
        machine_hash.update(machine_id.as_bytes());
        let machine_hash = machine_hash.finalize();

        let stored_hash = &_blob[4..36];
        if stored_hash != machine_hash.as_slice() {
            return Err(TpmError::UnsealFailed);
        }

        let len_bytes = &_blob[36..40];
        let secret_len = u32::from_le_bytes(len_bytes.try_into().map_err(|_| TpmError::InvalidBlob)?) as usize;
        let expected_min = 40 + secret_len + 32;
        if _blob.len() < expected_min {
            return Err(TpmError::InvalidBlob);
        }

        let checksum_start = 40 + secret_len;
        let data = &_blob[..checksum_start];
        let checksum = &_blob[checksum_start..checksum_start + 32];
        if Self::checksum(data) != checksum {
            return Err(TpmError::InvalidBlob);
        }

        let key = Self::derive_key(&machine_hash);
        let mut secret = Vec::with_capacity(secret_len);
        let obfuscated = &_blob[40..40 + secret_len];
        for (idx, byte) in obfuscated.iter().enumerate() {
            secret.push(byte ^ key[idx % key.len()]);
        }

        Ok(secret)
    }

    pub fn require_available(&self) -> Result<(), TpmError> {
        if self.config.require_tpm && !self.is_available() {
            return Err(TpmError::NotAvailable);
        }
        Ok(())
    }

    fn machine_id(&self) -> Option<String> {
        if let Some(value) = &self.config.machine_id_override {
            return Some(value.clone());
        }

        let mut parts = Vec::new();

        #[cfg(target_os = "windows")]
        if let Some(machine_guid) = machine_guid_windows() {
            parts.push(format!("machine_guid:{machine_guid}"));
        }

        if let Ok(name) = std::env::var("COMPUTERNAME") {
            parts.push(format!("computername:{name}"));
        }

        if let Ok(name) = std::env::var("HOSTNAME") {
            parts.push(format!("hostname:{name}"));
        }

        if let Ok(cpu) = std::env::var("PROCESSOR_IDENTIFIER") {
            parts.push(format!("cpu:{cpu}"));
        }

        if let Ok(arch) = std::env::var("PROCESSOR_ARCHITECTURE") {
            parts.push(format!("arch:{arch}"));
        }

        if parts.is_empty() {
            return None;
        }

        let joined = parts.join("|");
        let mut hasher = Sha256::new();
        hasher.update(joined.as_bytes());
        let digest = hasher.finalize();
        Some(hex_lower(&digest))
    }

    fn derive_key(machine_hash: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(machine_hash);
        hasher.finalize().into()
    }

    fn checksum(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[cfg(all(feature = "real-tpm", target_os = "windows"))]
    fn seal_secret_real(&self, secret: &[u8]) -> Result<Vec<u8>, TpmError> {
        if !real_tpm_ready_windows() {
            return Err(TpmError::NotAvailable);
        }

        let protected = dpapi_protect_local_machine(secret)?;
        let mut blob = Vec::new();
        blob.extend_from_slice(b"TPMR");
        blob.extend_from_slice(&(protected.len() as u32).to_le_bytes());
        blob.extend_from_slice(&protected);
        let checksum = Self::checksum(&blob);
        blob.extend_from_slice(&checksum);
        Ok(blob)
    }

    #[cfg(all(feature = "real-tpm", target_os = "windows"))]
    fn unseal_secret_real(&self, blob: &[u8]) -> Result<Vec<u8>, TpmError> {
        if !real_tpm_ready_windows() {
            return Err(TpmError::NotAvailable);
        }

        if blob.len() < 4 + 4 + 32 {
            return Err(TpmError::InvalidBlob);
        }
        if &blob[0..4] != b"TPMR" {
            return Err(TpmError::InvalidBlob);
        }

        let protected_len = u32::from_le_bytes(
            blob[4..8]
                .try_into()
                .map_err(|_| TpmError::InvalidBlob)?,
        ) as usize;
        let expected_min = 8 + protected_len + 32;
        if blob.len() < expected_min {
            return Err(TpmError::InvalidBlob);
        }

        let checksum_start = 8 + protected_len;
        let data = &blob[..checksum_start];
        let checksum = &blob[checksum_start..checksum_start + 32];
        if Self::checksum(data) != checksum {
            return Err(TpmError::InvalidBlob);
        }

        let protected = &blob[8..8 + protected_len];
        dpapi_unprotect_local_machine(protected)
    }
}

fn hex_lower(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(target_os = "windows")]
fn machine_guid_windows() -> Option<String> {
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if !line.contains("MachineGuid") {
            continue;
        }

        // Typical format: MachineGuid    REG_SZ    {value}
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(value) = fields.last() {
            if !value.is_empty() {
                return Some((*value).to_string());
            }
        }
    }

    None
}

#[cfg(all(feature = "real-tpm", target_os = "windows"))]
fn real_tpm_ready_windows() -> bool {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$t=Get-Tpm; if($t.TpmPresent -and $t.TpmReady){'true'} else {'false'}",
        ])
        .output();

    let Ok(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_tpm_ready_output(&stdout)
}

#[cfg(all(feature = "real-tpm", target_os = "windows"))]
fn dpapi_protect_local_machine(secret: &[u8]) -> Result<Vec<u8>, TpmError> {
    let input_b64 = general_purpose::STANDARD.encode(secret);
    let script = format!(
        "$in='{}'; $bytes=[Convert]::FromBase64String($in); $enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine); [Convert]::ToBase64String($enc)",
        input_b64
    );
    let out = run_powershell_capture_stdout(&script)?;
    general_purpose::STANDARD
        .decode(out.trim().as_bytes())
        .map_err(|_| TpmError::PlatformFailure)
}

#[cfg(all(feature = "real-tpm", target_os = "windows"))]
fn dpapi_unprotect_local_machine(protected: &[u8]) -> Result<Vec<u8>, TpmError> {
    let input_b64 = general_purpose::STANDARD.encode(protected);
    let script = format!(
        "$in='{}'; $bytes=[Convert]::FromBase64String($in); $dec=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine); [Convert]::ToBase64String($dec)",
        input_b64
    );
    let out = run_powershell_capture_stdout(&script)?;
    general_purpose::STANDARD
        .decode(out.trim().as_bytes())
        .map_err(|_| TpmError::PlatformFailure)
}

#[cfg(all(feature = "real-tpm", target_os = "windows"))]
fn run_powershell_capture_stdout(script: &str) -> Result<String, TpmError> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|_| TpmError::PlatformFailure)?;

    if !output.status.success() {
        return Err(TpmError::PlatformFailure);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(all(feature = "real-tpm", target_os = "windows"))]
fn parse_tpm_ready_output(output: &str) -> bool {
    output.lines().any(|line| line.trim().eq_ignore_ascii_case("true"))
}

#[cfg(all(test, feature = "real-tpm", target_os = "windows"))]
mod tests {
    use super::parse_tpm_ready_output;

    #[test]
    fn parse_tpm_ready_true() {
        assert!(parse_tpm_ready_output("true\r\n"));
        assert!(parse_tpm_ready_output("  TRUE  \n"));
    }

    #[test]
    fn parse_tpm_ready_false() {
        assert!(!parse_tpm_ready_output("false\r\n"));
        assert!(!parse_tpm_ready_output("unexpected\r\n"));
    }
}
