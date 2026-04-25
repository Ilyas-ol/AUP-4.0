param(
    [string]$PayloadPath = "licenses\payload.json",
    [string]$LicensePath = "licenses\license.signed.json",
    [string]$PrivateKeyPath = "licenses\keys\private.key",
    [string]$PublicKeyPath = "licenses\keys\public.key",
    [string]$RuntimeInputPath = "licenses\runtime_input.simulation.json",
    [string]$IssuedAt = "2026-04-25"
)

function Write-RuntimeInput {
    param(
        [int]$RequestedUsers = 1,
        [string[]]$RequestedModules = @("core"),
        [string]$MachineBinding = $null,
        [int]$RiskSignal = 0,
        [bool]$HoneypotCalled = $false,
        [int]$ActiveUsers = 1,
        [int]$ModuleSwitches = 0,
        [int]$RequestRate = 1
    )

    $inputObj = @{
        requested_users = $RequestedUsers
        requested_modules = $RequestedModules
        machine_binding = $MachineBinding
        risk_signal = $RiskSignal
        honeypot_called = $HoneypotCalled
        telemetry = @{
            active_users = $ActiveUsers
            module_switches = $ModuleSwitches
            request_rate = $RequestRate
        }
    }

    $inputObj | ConvertTo-Json -Depth 4 | Set-Content -Path $RuntimeInputPath
}

function Run-Step {
    param([string]$Title, [scriptblock]$Body)
    Write-Host "" 
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    & $Body
}

Run-Step "Generate keys" {
    cargo run -p license-issuer -- gen-keys --out-private $PrivateKeyPath --out-public $PublicKeyPath
}

Run-Step "Write payload" {
    @"
{
  "license_id": "LIC-DEMO",
  "customer_id": "CUST-01",
  "product_id": "PROD-A",
  "modules": ["core"],
  "max_users": 10,
  "valid_from": "2026-01-01",
  "valid_to": "2026-12-31",
  "environment_type": "on-prem",
  "machine_binding": null,
  "binary_hash": null,
  "issued_at": "$IssuedAt",
  "version": 1
}
"@ | Set-Content -Path $PayloadPath
}

Run-Step "Sign license" {
    cargo run -p license-issuer -- issue --payload $PayloadPath --private-key $PrivateKeyPath --out $LicensePath
}

Run-Step "Normal run (should PASS)" {
    Write-RuntimeInput
    cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
}

Run-Step "Crack attempt: honeypot (should DENY)" {
    Write-RuntimeInput -HoneypotCalled $true
    cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
}

Run-Step "Suspicious context: risk signal high (should route DECOY)" {
    Write-RuntimeInput -RiskSignal 5
    cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
}

Run-Step "Anomaly spike (should DENY)" {
    Write-RuntimeInput -ActiveUsers 999
    cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
}

Run-Step "Abuse attempt: too many users (should DENY)" {
    Write-RuntimeInput -RequestedUsers 999
    cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
}

Write-Host "" 
Write-Host "Demo complete." -ForegroundColor Green
