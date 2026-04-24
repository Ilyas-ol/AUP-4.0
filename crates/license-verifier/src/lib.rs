use license_core::{verify_signed, LicenseError, LicensePayload, SignedLicense};
use std::fs;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("io error")]
    Io,
    #[error("invalid license")]
    Invalid,
    #[error("license constraint failed")]
    ConstraintFailed,
}

#[derive(Debug, Clone)]
pub struct LicenseConstraints {
    pub today: String,
    pub requested_users: u32,
    pub requested_modules: Vec<String>,
    pub machine_binding: Option<String>,
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

pub fn validate_dates(payload: &LicensePayload, today: &str) -> Result<(), VerifyError> {
    if today < payload.valid_from.as_str() || today > payload.valid_to.as_str() {
        return Err(VerifyError::ConstraintFailed);
    }
    Ok(())
}

pub fn validate_constraints(payload: &LicensePayload, constraints: &LicenseConstraints) -> Result<(), VerifyError> {
    validate_dates(payload, &constraints.today)?;

    if constraints.requested_users > payload.max_users {
        return Err(VerifyError::ConstraintFailed);
    }

    for module in &constraints.requested_modules {
        if !payload.modules.iter().any(|m| m == module) {
            return Err(VerifyError::ConstraintFailed);
        }
    }

    if let Some(expected) = &payload.machine_binding {
        if Some(expected) != constraints.machine_binding.as_ref() {
            return Err(VerifyError::ConstraintFailed);
        }
    }

    Ok(())
}
