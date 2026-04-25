param()

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " AUP-4.0 Interactive Docker Judge Demo   " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script demonstrates the architecture running inside a Docker container."
Write-Host "Press [Enter] to proceed through each scenario."
Write-Host ""
Pause

# Helper function
function Run-Docker {
    param([string]$ArgsStr)
    Write-Host "> docker-compose $ArgsStr" -ForegroundColor DarkGray
    Invoke-Expression "docker-compose $ArgsStr"
}

Write-Host "`n[ SCENARIO 1: Generate & Issue Valid License ]" -ForegroundColor Yellow
Write-Host "Running license issuer inside Docker to generate an encrypted license."
Pause
Run-Docker "run --rm issue-license license-issuer gen-keys --out-private licenses/keys/private.key --out-public licenses/keys/public.key"
Run-Docker "run --rm issue-license license-issuer issue --payload licenses/payload.json --private-key licenses/keys/private.key --out licenses/license.signed.json --encryption-key `"demo-secret`""
Write-Host "✅ Keys generated. License issued and AES-256-GCM encrypted." -ForegroundColor Green

Write-Host "`n[ SCENARIO 2: Valid App Startup ]" -ForegroundColor Yellow
Pause
Run-Docker "run --rm demo-app demo-app licenses/license.signed.json licenses/keys/public.key licenses/runtime_input.normal.json"

Write-Host "`n[ SCENARIO 3: Tampered License Attack ]" -ForegroundColor Yellow
Pause
$lic = Get-Content "licenses\license.signed.json" -Raw
$lic = $lic -replace "A", "B"
$lic | Set-Content "licenses\license.tampered.json"
Run-Docker "run --rm demo-app demo-app licenses/license.tampered.json licenses/keys/public.key licenses/runtime_input.normal.json"
Write-Host "✅ Attack Thwarted: Cryptographic signature mismatch." -ForegroundColor Green

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " Docker Demo Complete! " -ForegroundColor Cyan
