use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid key")]
    InvalidKey,
    #[error("serialization error")]
    Serialization,
    #[error("crypto error")]
    Crypto,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedLicense {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
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

pub fn encrypt_license(signed_json: &str, key: &[u8; 32]) -> Result<String, LicenseError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, signed_json.as_bytes())
        .map_err(|_| LicenseError::Crypto)?;

    let enc = EncryptedLicense {
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
        nonce_b64: general_purpose::STANDARD.encode(nonce_bytes),
    };

    serde_json::to_string(&enc).map_err(|_| LicenseError::Serialization)
}

pub fn decrypt_license(encrypted_json: &str, key: &[u8; 32]) -> Result<String, LicenseError> {
    if let Ok(enc) = serde_json::from_str::<EncryptedLicense>(encrypted_json) {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_bytes = general_purpose::STANDARD
            .decode(enc.nonce_b64.as_bytes())
            .map_err(|_| LicenseError::InvalidKey)?;
        let ciphertext = general_purpose::STANDARD
            .decode(enc.ciphertext_b64.as_bytes())
            .map_err(|_| LicenseError::InvalidKey)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| LicenseError::Crypto)?;
        
        String::from_utf8(plaintext).map_err(|_| LicenseError::Serialization)
    } else {
        Ok(encrypted_json.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let (priv_b64, pub_b64) = generate_keypair();
        let payload = LicensePayload {
            license_id: "LIC-001".to_string(),
            customer_id: "CUST-01".to_string(),
            product_id: "PROD-A".to_string(),
            modules: vec!["core".to_string()],
            max_users: 10,
            valid_from: "2026-01-01".to_string(),
            valid_to: "2026-12-31".to_string(),
            environment_type: "on-prem".to_string(),
            machine_binding: None,
            binary_hash: None,
            issued_at: "2026-04-24".to_string(),
            version: 1,
        };

        let signed = sign_payload(&payload, &priv_b64).expect("sign");
        let verified = verify_signed(&signed, &pub_b64).expect("verify");
        assert_eq!(verified.license_id, payload.license_id);
        assert_eq!(verified.max_users, payload.max_users);
    }
}
