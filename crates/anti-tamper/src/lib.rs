use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("hash mismatch")]
    HashMismatch,
    #[error("io error")]
    Io,
}

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn verify_hash(expected: [u8; 32], actual: [u8; 32]) -> Result<(), IntegrityError> {
    if expected == actual {
        Ok(())
    } else {
        Err(IntegrityError::HashMismatch)
    }
}

pub fn hash_file(path: &std::path::Path) -> Result<[u8; 32], IntegrityError> {
    let data = std::fs::read(path).map_err(|_| IntegrityError::Io)?;
    Ok(hash_bytes(&data))
}

pub fn verify_file_hash(path: &std::path::Path, expected: [u8; 32]) -> Result<(), IntegrityError> {
    let actual = hash_file(path)?;
    verify_hash(expected, actual)
}
