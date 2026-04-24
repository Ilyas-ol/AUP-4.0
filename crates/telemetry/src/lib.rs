use aes_gcm::{aead::Aead, Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("io error")]
    Io,
    #[error("crypto error")]
    Crypto,
    #[error("serialization error")]
    Serialization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub timestamp: String,
    pub event_type: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedBlob {
    nonce_b64: String,
    ciphertext_b64: String,
}

pub struct TelemetryStore {
    path: PathBuf,
    key: [u8; 32],
}

impl TelemetryStore {
    pub fn new(path: PathBuf, key: [u8; 32]) -> Self {
        Self { path, key }
    }

    pub fn append_event(&self, event: TelemetryEvent) -> Result<(), TelemetryError> {
        let mut events = self.load_events()?;
        events.push(event);
        self.save_events(&events)
    }

    pub fn load_events(&self) -> Result<Vec<TelemetryEvent>, TelemetryError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&self.path).map_err(|_| TelemetryError::Io)?;
        let blob: EncryptedBlob = serde_json::from_str(&data).map_err(|_| TelemetryError::Serialization)?;
        let nonce = general_purpose::STANDARD
            .decode(blob.nonce_b64.as_bytes())
            .map_err(|_| TelemetryError::Serialization)?;
        let ciphertext = general_purpose::STANDARD
            .decode(blob.ciphertext_b64.as_bytes())
            .map_err(|_| TelemetryError::Serialization)?;

        let cipher = Aes256Gcm::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| TelemetryError::Crypto)?;
        serde_json::from_slice(&plaintext).map_err(|_| TelemetryError::Serialization)
    }

    pub fn save_events(&self, events: &[TelemetryEvent]) -> Result<(), TelemetryError> {
        let plaintext = serde_json::to_vec(events).map_err(|_| TelemetryError::Serialization)?;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| TelemetryError::Crypto)?;

        let blob = EncryptedBlob {
            nonce_b64: general_purpose::STANDARD.encode(nonce),
            ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
        };
        let encoded = serde_json::to_string_pretty(&blob).map_err(|_| TelemetryError::Serialization)?;
        fs::write(&self.path, encoded).map_err(|_| TelemetryError::Io)
    }

    pub fn clear(&self) -> Result<(), TelemetryError> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|_| TelemetryError::Io)?;
        }
        Ok(())
    }

    pub fn upload_with<F>(&self, uploader: F) -> Result<(), TelemetryError>
    where
        F: Fn(&[TelemetryEvent]) -> Result<(), TelemetryError>,
    {
        let events = self.load_events()?;
        if events.is_empty() {
            return Ok(());
        }
        uploader(&events)?;
        self.clear()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
