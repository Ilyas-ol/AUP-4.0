use sha2::{Digest, Sha256};

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
}

pub struct TpmBinding {
    config: TpmBindingConfig,
}

impl TpmBinding {
    pub fn new(config: TpmBindingConfig) -> Self {
        Self { config }
    }

    pub fn is_available(&self) -> bool {
        // Simulated TPM always available unless require_tpm is true and no machine id.
        self.machine_id().is_some()
    }

    pub fn seal_secret(&self, _secret: &[u8]) -> Result<Vec<u8>, TpmError> {
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
        std::env::var("COMPUTERNAME").ok()
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
}
