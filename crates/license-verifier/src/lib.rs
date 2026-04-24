use license_core::{verify_signed, LicenseError, LicensePayload, SignedLicense};
use std::fs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io error")]
    Io,
    #[error("invalid license")]
    Invalid,
}

pub fn verify_from_file(path: &Path, public_key_b64: &str) -> Result<LicensePayload, VerifyError> {
    let data = fs::read_to_string(path).map_err(|_| VerifyError::Io)?;
    let signed: SignedLicense = serde_json::from_str(&data).map_err(|_| VerifyError::Invalid)?;
    verify_signed(&signed, public_key_b64).map_err(|_| VerifyError::Invalid)
}

pub fn verify_from_str(data: &str, public_key_b64: &str) -> Result<LicensePayload, VerifyError> {
    let signed: SignedLicense = serde_json::from_str(data).map_err(|_| VerifyError::Invalid)?;
    verify_signed(&signed, public_key_b64).map_err(|_| VerifyError::Invalid)
}

pub fn verify_from_signed(signed: &SignedLicense, public_key_b64: &str) -> Result<LicensePayload, VerifyError> {
    verify_signed(signed, public_key_b64).map_err(|_| VerifyError::Invalid)
}

pub fn validate_dates(_payload: &LicensePayload, _today: &str) -> Result<(), VerifyError> {
    // TODO: add date parsing/validation
    Ok(())
}
