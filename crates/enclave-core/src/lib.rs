use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("enclave initialization failed")]
    InitFailed,
    #[error("integrity check failed")]
    IntegrityFailed,
    #[error("crypto operation failed")]
    CryptoFailed,
    #[error("operation not implemented")]
    NotImplemented,
}

/// Sealed data produced by the enclave, containing nonce + ciphertext.
#[derive(Debug, Clone)]
pub struct SealedData {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Simulated SGX enclave boundary.
///
/// In a real SGX deployment, the code inside `execute_trusted`, `seal`, and
/// `unseal` would run inside an enclave where the OS and debugger cannot read
/// memory. Here we simulate the boundary by:
///   1. Using AES-256-GCM to encrypt/decrypt data crossing the boundary.
///   2. Zeroizing plaintext secrets after use.
///   3. Maintaining an internal integrity nonce that proves the enclave was
///      properly initialized before any operation.
pub struct Enclave {
    initialized: bool,
    /// Random nonce generated at init; used as proof-of-init in integrity checks.
    init_nonce: [u8; 32],
}

impl Enclave {
    pub fn new() -> Self {
        Self {
            initialized: false,
            init_nonce: [0u8; 32],
        }
    }

    /// Initialize the enclave.  In real SGX this would call `sgx_create_enclave`.
    pub fn init(&mut self) -> Result<(), EnclaveError> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        self.init_nonce = nonce;
        self.initialized = true;
        Ok(())
    }

    /// Verify enclave integrity by checking that the init nonce is non-zero.
    pub fn integrity_check(&self) -> Result<(), EnclaveError> {
        if !self.initialized || self.init_nonce.iter().all(|&b| b == 0) {
            return Err(EnclaveError::IntegrityFailed);
        }
        Ok(())
    }

    /// Encrypt (seal) data inside the enclave boundary.
    ///
    /// The key never leaves the enclave; in real SGX it would be derived from
    /// the enclave sealing key.
    pub fn seal(&self, key: &[u8; 32], plaintext: &[u8]) -> Result<SealedData, EnclaveError> {
        if !self.initialized {
            return Err(EnclaveError::InitFailed);
        }

        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| EnclaveError::CryptoFailed)?;

        Ok(SealedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt (unseal) data inside the enclave boundary.
    ///
    /// Returns the plaintext.  The caller should zeroize it when done.
    pub fn unseal(&self, key: &[u8; 32], sealed: &SealedData) -> Result<Vec<u8>, EnclaveError> {
        if !self.initialized {
            return Err(EnclaveError::InitFailed);
        }

        let aes_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&sealed.nonce);

        let plaintext = cipher
            .decrypt(nonce, sealed.ciphertext.as_ref())
            .map_err(|_| EnclaveError::CryptoFailed)?;

        Ok(plaintext)
    }

    /// Execute trusted logic: seal input, process inside boundary, return result.
    ///
    /// This simulates moving data into the enclave, processing, and returning
    /// only the result.  The plaintext inside the enclave is zeroized after use.
    pub fn execute_trusted(&self, key: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        if !self.initialized {
            return Err(EnclaveError::InitFailed);
        }

        // Seal the input (simulates enclave receiving encrypted data)
        let sealed = self.seal(key, input)?;

        // Unseal inside enclave boundary (simulates enclave decrypting)
        let mut plaintext = self.unseal(key, &sealed)?;

        // --- Process inside enclave (here: identity; real use: license validation) ---
        let result = plaintext.clone();

        // Wipe plaintext from enclave memory
        plaintext.zeroize();

        Ok(result)
    }

    /// Returns whether the enclave is currently initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_and_integrity() {
        let mut enclave = Enclave::new();
        assert!(enclave.integrity_check().is_err());
        enclave.init().unwrap();
        assert!(enclave.integrity_check().is_ok());
    }

    #[test]
    fn seal_unseal_round_trip() {
        let mut enclave = Enclave::new();
        enclave.init().unwrap();

        let key = [42u8; 32];
        let data = b"license-secret-payload";

        let sealed = enclave.seal(&key, data).unwrap();
        assert_ne!(sealed.ciphertext.as_slice(), data);

        let unsealed = enclave.unseal(&key, &sealed).unwrap();
        assert_eq!(unsealed, data);
    }

    #[test]
    fn seal_fails_before_init() {
        let enclave = Enclave::new();
        let key = [1u8; 32];
        assert!(enclave.seal(&key, b"data").is_err());
    }

    #[test]
    fn unseal_wrong_key_fails() {
        let mut enclave = Enclave::new();
        enclave.init().unwrap();

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let sealed = enclave.seal(&key1, b"secret").unwrap();
        assert!(enclave.unseal(&key2, &sealed).is_err());
    }

    #[test]
    fn execute_trusted_round_trip() {
        let mut enclave = Enclave::new();
        enclave.init().unwrap();

        let key = [99u8; 32];
        let input = b"trusted-input";
        let output = enclave.execute_trusted(&key, input).unwrap();
        assert_eq!(output, input);
    }
}
