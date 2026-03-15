# update_proxy.ps1 - Met a jour le champ proxy dans config\config.json
# Appele par lancer.bat avec -ProxyActive 0|1
# Note: utilise [System.IO.File]::WriteAllText pour ecrire en UTF-8 sans BOM
#       (Set-Content -Encoding UTF8 ajoute un BOM qui casse le parser JSON de Go)
param([int]$ProxyActive)

$configPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "config\config.json"
if (-not (Test-Path $configPath)) {
    Write-Host "  [WARN] config\config.json introuvable : $configPath"
    exit 0
}

$raw = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
$cfg = $raw | ConvertFrom-Json

if ($ProxyActive -eq 0) {
    $cfg.proxy = ""
    Write-Host "  -> proxy vide : connexion directe a https://sandbox.recordedfuture.com"
} else {
    Write-Host "  -> proxy conserve : $($cfg.proxy)"
}

$json = $cfg | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($configPath, $json, (New-Object System.Text.UTF8Encoding $false))
