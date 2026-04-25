param(
    [string]$PayloadPath = "licenses\payload.json",
    [string]$LicensePath = "licenses\license.signed.json",
    [string]$PrivateKeyPath = "licenses\keys\private.key",
    [string]$PublicKeyPath = "licenses\keys\public.key",
    [string]$IssuedAt = "2026-04-25",
    [string]$Today = "2026-06-01"
)

function Reset-DemoEnv {
    Remove-Item Env:REQ_USERS,Env:REQ_MODULES,Env:TODAY,Env:MACHINE_BINDING,Env:HONEYPOT,Env:SIM_DEBUGGER,Env:SIM_INJECT,Env:SIM_VM -ErrorAction SilentlyContinue
}

function Run-Step {
    param([string]$Title, [scriptblock]$Body)
    Write-Host "" 
    Write-Host "=== $Title ===" -ForegroundColor Cyan
    & $Body
}

Reset-DemoEnv

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
    Reset-DemoEnv
    $env:TODAY = $Today
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Run-Step "Crack attempt: honeypot (should DENY)" {
    Reset-DemoEnv
    $env:TODAY = $Today
    $env:HONEYPOT = "1"
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Run-Step "Crack attempt: debugger (should DENY)" {
    Reset-DemoEnv
    $env:TODAY = $Today
    $env:SIM_DEBUGGER = "1"
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Run-Step "Crack attempt: injection (should DENY)" {
    Reset-DemoEnv
    $env:TODAY = $Today
    $env:SIM_INJECT = "1"
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Run-Step "Crack attempt: VM (should DENY)" {
    Reset-DemoEnv
    $env:TODAY = $Today
    $env:SIM_VM = "1"
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Run-Step "Abuse attempt: too many users (should DENY)" {
    Reset-DemoEnv
    $env:TODAY = $Today
    $env:REQ_USERS = "999"
    cargo run -p demo-app -- $LicensePath $PublicKeyPath
}

Reset-DemoEnv
Write-Host "" 
Write-Host "Demo complete." -ForegroundColor Green
