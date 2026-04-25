use detection_layer::TelemetrySnapshot;
use license_verifier::LicenseConstraints;
use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorInput};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RuntimeTelemetry {
    active_users: u32,
    module_switches: u32,
    request_rate: u32,
}

impl Default for RuntimeTelemetry {
    fn default() -> Self {
        Self {
            active_users: 1,
            module_switches: 0,
            request_rate: 1,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RuntimeInput {
    requested_users: u32,
    requested_modules: Vec<String>,
    machine_binding: Option<String>,
    risk_signal: u8,
    honeypot_called: bool,
    telemetry: RuntimeTelemetry,
}

impl Default for RuntimeInput {
    fn default() -> Self {
        Self {
            requested_users: 1,
            requested_modules: vec!["core".to_string()],
            machine_binding: None,
            risk_signal: 0,
            honeypot_called: false,
            telemetry: RuntimeTelemetry::default(),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: demo-app <license.json> <public_key.txt> <runtime_input.json>");
        std::process::exit(2);
    }

    let license_path = &args[1];
    let public_key_path = &args[2];
    let runtime_input_path = &args[3];

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

    let runtime_data = match fs::read_to_string(runtime_input_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Failed to read runtime input: {err}");
            std::process::exit(1);
        }
    };

    let runtime_input: RuntimeInput = match serde_json::from_str(&runtime_data) {
        Ok(input) => input,
        Err(err) => {
            eprintln!("Failed to parse runtime input JSON: {err}");
            std::process::exit(1);
        }
    };

    let today = current_utc_date();
    let requested_modules = if runtime_input.requested_modules.is_empty() {
        vec!["core".to_string()]
    } else {
        runtime_input.requested_modules
    };

    let telemetry_path = "telemetry.json".to_string();
    let telemetry_key = [9u8; 32];

    let mut orchestrator = Orchestrator::new(OrchestratorConfig {
        require_tpm: true,
        anomaly_threshold: 10,
        telemetry_path: PathBuf::from(telemetry_path),
        telemetry_key,
        state_path: PathBuf::from("license_state.json"),
    });

    // Resolve binary path for anti-tamper hash check
    let binary_path = std::env::current_exe().ok();

    let input = OrchestratorInput {
        secret: b"demo-secret".to_vec(),
        tpm_blob: None,
        risk_signal: runtime_input.risk_signal,
        telemetry: TelemetrySnapshot {
            active_users: runtime_input.telemetry.active_users,
            module_switches: runtime_input.telemetry.module_switches,
            request_rate: runtime_input.telemetry.request_rate,
        },
        honeypot_called: runtime_input.honeypot_called,
        license_data,
        license_public_key_b64: public_key_b64,
        license_constraints: LicenseConstraints {
            today,
            requested_users: runtime_input.requested_users,
            requested_modules,
            machine_binding: runtime_input.machine_binding,
        },
        binary_path,
    };

    match orchestrator.run(input) {
        Ok(result) => {
            if result.silent_kill {
                eprintln!("APP START: DENIED (silent kill)");
                std::process::exit(1);
            }
            
            // --- Distributed Check: Secondary validation away from main initialization ---
            // Simulates checking the license state again later in the application flow.
            if !result.license_ok {
                eprintln!("SECONDARY CHECK: DENIED (license invalidated)");
                std::process::exit(1);
            }

            println!("APP START: OK (route: {:?})", result.route);
            
            // --- Normal application execution starts here ---
            println!("Application running... (Press Ctrl+C to exit)");
        }
        Err(err) => {
            eprintln!("APP START: DENIED ({err})");
            std::process::exit(1);
        }
    }
}

fn current_utc_date() -> String {
    OffsetDateTime::now_utc().date().to_string()
}
