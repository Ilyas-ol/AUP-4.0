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
    },
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenKeys { out_private, out_public } => {
            let (priv_b64, pub_b64) = generate_keypair();
            fs::write(out_private, priv_b64).map_err(|e| e.to_string())?;
            fs::write(out_public, pub_b64).map_err(|e| e.to_string())?;
        }
        Command::Issue { payload, private_key, out } => {
            let payload_json = fs::read_to_string(payload).map_err(|e| e.to_string())?;
            let payload: LicensePayload = serde_json::from_str(&payload_json).map_err(|e| e.to_string())?;
            let priv_b64 = fs::read_to_string(private_key).map_err(|e| e.to_string())?;
            let signed: SignedLicense = sign_payload(&payload, priv_b64.trim()).map_err(|e| e.to_string())?;
            let output = serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())?;
            fs::write(out, output).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}
