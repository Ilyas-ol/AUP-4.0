use detection_layer::TelemetrySnapshot;
use license_verifier::LicenseConstraints;
use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorInput};
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: demo-app <license.json> <public_key.txt>");
        std::process::exit(2);
    }

    let license_path = &args[1];
    let public_key_path = &args[2];

    let license_data = match fs::read_to_string(license_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read license: {err}");
            std::process::exit(1);
        }
    };

    let public_key_b64 = match fs::read_to_string(public_key_path) {
        Ok(data) => data.trim().to_string(),
        Err(err) => {
            eprintln!("Failed to read public key: {err}");
            std::process::exit(1);
        }
    };

    let requested_users = env_value_u32("REQ_USERS", 1);
    let requested_modules = env_value_list("REQ_MODULES");
    let today = env::var("TODAY").unwrap_or_else(|_| "2026-06-01".to_string());
    let machine_binding = env::var("MACHINE_BINDING").ok();
    let risk_signal = env_value_u8("RISK_SIGNAL", 0);
    let honeypot_called = env_flag("HONEYPOT");

    let telemetry_path = env::var("TELEMETRY_PATH").unwrap_or_else(|_| "telemetry.json".to_string());
    let telemetry_key = [9u8; 32];

    let mut orchestrator = Orchestrator::new(OrchestratorConfig {
        require_tpm: false,
        anomaly_threshold: 10,
        telemetry_path: PathBuf::from(telemetry_path),
        telemetry_key,
    });

    let input = OrchestratorInput {
        secret: b"demo-secret".to_vec(),
        tpm_blob: None,
        risk_signal,
        telemetry: TelemetrySnapshot {
            active_users: requested_users,
            module_switches: 0,
            request_rate: 1,
        },
        honeypot_called,
        license_data,
        license_public_key_b64: public_key_b64,
        license_constraints: LicenseConstraints {
            today,
            requested_users,
            requested_modules,
            machine_binding,
        },
    };

    match orchestrator.run(input) {
        Ok(result) => {
            if result.silent_kill {
                eprintln!("APP START: DENIED (silent kill)");
                std::process::exit(1);
            }
            println!("APP START: OK (route: {:?})", result.route);
        }
        Err(err) => {
            eprintln!("APP START: DENIED ({err})");
            std::process::exit(1);
        }
    }
}

fn env_flag(key: &str) -> bool {
    env::var(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn env_value_u32(key: &str, default: u32) -> u32 {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_value_u8(key: &str, default: u8) -> u8 {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_value_list(key: &str) -> Vec<String> {
    env::var(key)
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_else(|| vec!["core".to_string()])
}
