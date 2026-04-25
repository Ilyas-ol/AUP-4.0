param(
    [string]$LicensePath = "licenses\sample.lic",
    [string]$PublicKeyPath = "licenses\keys\public.key",
    [string]$RuntimeInputPath = "licenses\runtime_input.normal.json"
)

@"
{
    "requested_users": 1,
    "requested_modules": ["core"],
    "machine_binding": null,
    "risk_signal": 0,
    "honeypot_called": false,
    "telemetry": {
        "active_users": 1,
        "module_switches": 0,
        "request_rate": 1
    }
}
"@ | Set-Content -Path $RuntimeInputPath

cargo run -p demo-app -- $LicensePath $PublicKeyPath $RuntimeInputPath
