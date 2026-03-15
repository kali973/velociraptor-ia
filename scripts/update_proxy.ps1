# update_proxy.ps1 - Met a jour le champ proxy_url dans config\config.json
# Appele par lancer.bat avec -ProxyActive 0|1
param([int]$ProxyActive)

$configPath = Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) "config\config.json"

if (-not (Test-Path $configPath)) {
    # Creer config.json avec les valeurs par defaut si absent
    $configDir = Split-Path -Parent $configPath
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    $defaultCfg = @{
        velociraptor_bin = ""
        output_dir       = "..\collections"
        reports_dir      = "..\reports"
        ui_port          = "8767"
        proxy_url        = ""
        tls_skip_verify  = $false
        proxy_auth_type  = ""
        proxy_user       = ""
        proxy_pass       = ""
        moteur_dir       = ""
    }
    $defaultCfg | ConvertTo-Json -Depth 5 |
        ForEach-Object { [System.IO.File]::WriteAllText($configPath, $_, (New-Object System.Text.UTF8Encoding $false)) }
    Write-Host "  [OK] config\config.json cree avec les valeurs par defaut."
}

$raw = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
$cfg = $raw | ConvertFrom-Json

if ($ProxyActive -eq 0) {
    $cfg.proxy_url = ""
    Write-Host "  -> proxy_url vide : connexion directe"
} else {
    Write-Host "  -> proxy_url conserve : $($cfg.proxy_url)"
}

$json = $cfg | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($configPath, $json, (New-Object System.Text.UTF8Encoding $false))
