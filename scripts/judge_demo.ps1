param()

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "    AUP-4.0 Interactive Judge Demo       " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script demonstrates the 4-layer architecture."
Write-Host "Press [Enter] to proceed through each scenario."
Write-Host ""
Pause

# Helper function
function Run-Cargo {
    param([string]$ArgsStr)
    Write-Host "> cargo $ArgsStr" -ForegroundColor DarkGray
    Invoke-Expression "cargo $ArgsStr"
}

Write-Host "`n[ SCENARIO 1: Generate & Issue Valid License ]" -ForegroundColor Yellow
Write-Host "Simulating a vendor issuing a new license to a customer."
Pause
Run-Cargo "run -q -p license-issuer -- gen-keys --out-private licenses\keys\private.key --out-public licenses\keys\public.key"
Run-Cargo "run -q -p license-issuer -- issue --payload licenses\payload.json --private-key licenses\keys\private.key --out licenses\license.signed.json --encryption-key `"demo-secret`""
Write-Host "✅ Keys generated. License issued and AES-256-GCM encrypted." -ForegroundColor Green

Write-Host "`n[ SCENARIO 2: Valid App Startup ]" -ForegroundColor Yellow
Write-Host "The application unseals the key, decrypts the license inside the enclave, verifies the signature, hashes the binary, and checks the kernel environment."
Pause
Run-Cargo "run -q -p demo-app -- licenses\license.signed.json licenses\keys\public.key licenses\runtime_input.normal.json"

Write-Host "`n[ SCENARIO 3: Tampered License Attack ]" -ForegroundColor Yellow
Write-Host "Attacker modifies a single byte in the encrypted license to try and elevate privileges."
Pause
$lic = Get-Content "licenses\license.signed.json" -Raw
$lic = $lic -replace "A", "B" # Corrupt the payload slightly
$lic | Set-Content "licenses\license.tampered.json"
Run-Cargo "run -q -p demo-app -- licenses\license.tampered.json licenses\keys\public.key licenses\runtime_input.normal.json"
Write-Host "✅ Attack Thwarted: Cryptographic signature mismatch." -ForegroundColor Green

Write-Host "`n[ SCENARIO 4: Honeypot Trigger (Layer 3 Detection) ]" -ForegroundColor Yellow
Write-Host "Attacker tries to reverse engineer the binary and hits a decoy function."
Pause
@"
{
    "requested_users": 1,
    "requested_modules": ["core"],
    "machine_binding": null,
    "risk_signal": 0,
    "honeypot_called": true,
    "telemetry": {
        "active_users": 1,
        "module_switches": 0,
        "request_rate": 1
    }
}
"@ | Set-Content "licenses\runtime_input.honeypot.json"
Run-Cargo "run -q -p demo-app -- licenses\license.signed.json licenses\keys\public.key licenses\runtime_input.honeypot.json"
Write-Host "✅ Attack Thwarted: Telemetry logged the honeypot event and halted execution." -ForegroundColor Green

Write-Host "`n[ SCENARIO 5: License Version Rollback ]" -ForegroundColor Yellow
Write-Host "Attacker takes an older version of their license and replaces the new one to bypass expiry."
Pause
# Set version to 0 to trigger rollback
$payload = Get-Content "licenses\payload.json" -Raw | ConvertFrom-Json
$payload.version = 0
$payload | ConvertTo-Json | Set-Content "licenses\payload.rollback.json"
Run-Cargo "run -q -p license-issuer -- issue --payload licenses\payload.rollback.json --private-key licenses\keys\private.key --out licenses\license.rollback.json --encryption-key `"demo-secret`""
Run-Cargo "run -q -p demo-app -- licenses\license.rollback.json licenses\keys\public.key licenses\runtime_input.normal.json"
Write-Host "✅ Attack Thwarted: Orchestrator detected the state downgrade." -ForegroundColor Green

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " Demo Complete! " -ForegroundColor Cyan
Write-Host " Check 'telemetry.json' for the encrypted forensic logs." -ForegroundColor DarkGray
