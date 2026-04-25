use license_core::{verify_signed, LicensePayload, SignedLicense};
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> LicensePayload {
        LicensePayload {
            license_id: "LIC-TEST".to_string(),
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
    fn constraints_pass() {
        let payload = sample_payload();
        let constraints = LicenseConstraints {
            today: "2026-06-01".to_string(),
            requested_users: 3,
            requested_modules: vec!["core".to_string()],
            machine_binding: Some("MACHINE-1".to_string()),
        };
        assert!(validate_constraints(&payload, &constraints).is_ok());
    }

    #[test]
    fn constraints_fail_on_date() {
        let payload = sample_payload();
        let constraints = LicenseConstraints {
            today: "2025-12-31".to_string(),
            requested_users: 1,
            requested_modules: vec!["core".to_string()],
            machine_binding: Some("MACHINE-1".to_string()),
        };
        assert!(validate_constraints(&payload, &constraints).is_err());
    }

    #[test]
    fn constraints_fail_on_module() {
        let payload = sample_payload();
        let constraints = LicenseConstraints {
            today: "2026-06-01".to_string(),
            requested_users: 1,
            requested_modules: vec!["enterprise".to_string()],
            machine_binding: Some("MACHINE-1".to_string()),
        };
        assert!(validate_constraints(&payload, &constraints).is_err());
    }

    #[test]
    fn constraints_fail_on_users() {
        let payload = sample_payload();
        let constraints = LicenseConstraints {
            today: "2026-06-01".to_string(),
            requested_users: 10,
            requested_modules: vec!["core".to_string()],
            machine_binding: Some("MACHINE-1".to_string()),
        };
        assert!(validate_constraints(&payload, &constraints).is_err());
    }

    #[test]
    fn constraints_fail_on_machine() {
        let payload = sample_payload();
        let constraints = LicenseConstraints {
            today: "2026-06-01".to_string(),
            requested_users: 1,
            requested_modules: vec!["core".to_string()],
            machine_binding: Some("OTHER".to_string()),
        };
        assert!(validate_constraints(&payload, &constraints).is_err());
    }
}
