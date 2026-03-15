# update_proxy.ps1 - Met a jour le champ proxy_url dans config\config.json
# Appele par lancer.bat avec -ProxyActive 0|1
param([int]$ProxyActive)

$configPath = Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) "config\config.json"
if (-not (Test-Path $configPath)) {
    Write-Host "  [WARN] config\config.json introuvable : $configPath"
    exit 0
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
