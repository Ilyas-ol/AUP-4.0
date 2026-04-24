use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key")]
    InvalidKey,
    #[error("serialization error")]
    Serialization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub license_id: String,
    pub customer_id: String,
    pub product_id: String,
    pub modules: Vec<String>,
    pub max_users: u32,
    pub valid_from: String,
    pub valid_to: String,
    pub environment_type: String,
    pub machine_binding: Option<String>,
    pub binary_hash: Option<String>,
    pub issued_at: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    pub payload_json: String,
    pub signature_b64: String,
}

pub fn generate_keypair() -> (String, String) {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let priv_b64 = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let pub_b64 = general_purpose::STANDARD.encode(verifying_key.to_bytes());
    (priv_b64, pub_b64)
}

pub fn sign_payload(payload: &LicensePayload, private_key_b64: &str) -> Result<SignedLicense, LicenseError> {
    let payload_json = serde_json::to_string(payload).map_err(|_| LicenseError::Serialization)?;
    let key_bytes = general_purpose::STANDARD
        .decode(private_key_b64.as_bytes())
        .map_err(|_| LicenseError::InvalidKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes.try_into().map_err(|_| LicenseError::InvalidKey)?);

    let signature = signing_key.sign(payload_json.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    Ok(SignedLicense {
        payload_json,
        signature_b64,
    })
}

pub fn verify_signed(license: &SignedLicense, public_key_b64: &str) -> Result<LicensePayload, LicenseError> {
    let key_bytes = general_purpose::STANDARD
        .decode(public_key_b64.as_bytes())
        .map_err(|_| LicenseError::InvalidKey)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes.try_into().map_err(|_| LicenseError::InvalidKey)?)
        .map_err(|_| LicenseError::InvalidKey)?;

    let sig_bytes = general_purpose::STANDARD
        .decode(license.signature_b64.as_bytes())
        .map_err(|_| LicenseError::InvalidKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().map_err(|_| LicenseError::InvalidKey)?);

    verifying_key
        .verify(license.payload_json.as_bytes(), &signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    let payload = serde_json::from_str(&license.payload_json).map_err(|_| LicenseError::Serialization)?;
    Ok(payload)
}
