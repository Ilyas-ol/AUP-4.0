use clap::{Parser, Subcommand};
use license_core::{generate_keypair, sign_payload, LicensePayload, SignedLicense};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "license-issuer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenKeys {
        #[arg(long)]
        out_private: PathBuf,
        #[arg(long)]
        out_public: PathBuf,
    },
    Issue {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        encryption_key: Option<String>,
    },
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenKeys { out_private, out_public } => {
            let (priv_b64, pub_b64) = generate_keypair();
            std::fs::write(out_private, priv_b64).map_err(|e| e.to_string())?;
            std::fs::write(out_public, pub_b64).map_err(|e| e.to_string())?;
        }
        Command::Issue { payload, private_key, out, encryption_key } => {
            let payload_json = std::fs::read_to_string(payload).map_err(|e| e.to_string())?;
            let payload: LicensePayload = serde_json::from_str(&payload_json).map_err(|e| e.to_string())?;
            let priv_b64 = std::fs::read_to_string(private_key).map_err(|e| e.to_string())?;
            let signed: license_core::SignedLicense = license_core::sign_payload(&payload, priv_b64.trim()).map_err(|e| e.to_string())?;
            
            let signed_json = serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())?;

            let final_output = if let Some(key_str) = encryption_key {
                let mut k = [0u8; 32];
                let src = key_str.as_bytes();
                for (i, byte) in k.iter_mut().enumerate() {
                    *byte = src[i % src.len()];
                }
                license_core::encrypt_license(&signed_json, &k).map_err(|e| e.to_string())?
            } else {
                signed_json
            };

            std::fs::write(out, final_output).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}
