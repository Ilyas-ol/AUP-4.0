param(
    [string]$LicensePath = "licenses\sample.lic",
    [string]$PublicKeyPath = "licenses\keys\public.key"
)

$env:REQ_USERS = "1"
$env:REQ_MODULES = "core"
$env:TODAY = "2026-06-01"
$env:RISK_SIGNAL = "0"
$env:HONEYPOT = "true"
$env:TELEMETRY_PATH = "telemetry.json"

cargo run -p demo-app -- $LicensePath $PublicKeyPath
