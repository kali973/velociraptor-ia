# =============================================================================
# audit_securite.ps1 - Audit de securite du code source Velociraptor-IA
# Outils : gosec | govulncheck | gitleaks
# Sortie  : rapport TXT dans audit\ (+ PDF si audit.exe present)
# =============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$IHMDir     = Join-Path $ScriptDir "ia_forensic"
$ProjectDir = Split-Path -Parent $ScriptDir
$AuditDir   = Join-Path $ProjectDir "audit"
$Date       = Get-Date -Format "yyyy-MM-dd_HH-mm"
$TxtFile    = Join-Path $AuditDir "rapport_securite_$Date.txt"
$PdfFile    = Join-Path $AuditDir "rapport_securite_$Date.pdf"
$AuditExe   = Join-Path $ProjectDir "audit.exe"

$GoPath     = if ($env:GOPATH) { $env:GOPATH } else { Join-Path $env:USERPROFILE "go" }
$GoBin      = Join-Path $GoPath "bin"
$GosecExe   = Join-Path $GoBin "gosec.exe"
$GovulnExe  = Join-Path $GoBin "govulncheck.exe"
$GitleaksDir= Join-Path $ProjectDir "tools"
$GitleaksExe= Join-Path $GitleaksDir "gitleaks.exe"
$GitleaksURL= "https://github.com/gitleaks/gitleaks/releases/download/v8.23.3/gitleaks_8.23.3_windows_x64.zip"

New-Item -ItemType Directory -Path $AuditDir    -Force | Out-Null
New-Item -ItemType Directory -Path $GitleaksDir -Force | Out-Null

# Nettoyage anciens rapports
Get-ChildItem -Path $AuditDir -Filter "rapport_securite_*.txt" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 1 |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

$HasErrors  = $false
$HasSecrets = $false
$Sections   = @()

function Write-Status { param([string]$Line, [string]$Color="White"); Write-Host $Line -ForegroundColor $Color }

Write-Status ""
Write-Status "  ============================================================"
Write-Status "    Velociraptor-IA - Audit de Securite IHM"
Write-Status "    Date : $Date"
Write-Status "    Cible : scripts\ia_forensic\"
Write-Status "  ============================================================"
Write-Status ""

# Travailler sur le sous-repertoire IHM uniquement (pas le code Velociraptor entier)
Push-Location $IHMDir

# ===========================================================================
# OUTILS
# ===========================================================================
Write-Status "  [OUTILS] Verification des outils..."

if (-not (Test-Path $GosecExe)) {
    go install github.com/securego/gosec/v2/cmd/gosec@latest 2>&1 | Out-Null
    if (Test-Path $GosecExe) { Write-Status "  [OK] gosec installe." "Green" }
    else { Write-Status "  [!] gosec : echec installation." "Yellow" }
} else { Write-Status "  [OK] gosec present." }

if (-not (Test-Path $GovulnExe)) {
    go install golang.org/x/vuln/cmd/govulncheck@latest 2>&1 | Out-Null
    if (Test-Path $GovulnExe) { Write-Status "  [OK] govulncheck installe." "Green" }
    else { Write-Status "  [!] govulncheck : echec installation." "Yellow" }
} else { Write-Status "  [OK] govulncheck present." }

if (-not (Test-Path $GitleaksExe)) {
    $ZipPath = Join-Path $GitleaksDir "gitleaks.zip"
    try {
        Invoke-WebRequest -Uri $GitleaksURL -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $GitleaksDir -Force
        Remove-Item $ZipPath -ErrorAction SilentlyContinue
        if (Test-Path $GitleaksExe) { Write-Status "  [OK] gitleaks installe." "Green" }
    } catch { Write-Status "  [!] gitleaks : echec telechargement." "Yellow" }
} else { Write-Status "  [OK] gitleaks present." }

Write-Status ""

# ===========================================================================
# GOSEC
# ===========================================================================
Write-Status "  [1/3] GOSEC - Analyse statique code Go (ia_forensic/)"
$GosecLines  = @()
$GosecStatut = "OK"

if (Test-Path $GosecExe) {
    $RawOut = & $GosecExe -fmt text -severity medium -confidence medium -exclude G304,G107 ./... 2>&1
    $Issues = $RawOut | Where-Object { $_ -match "^\[G\d+\]" }
    if ($Issues.Count -gt 0) {
        $HasErrors = $true; $GosecStatut = "WARN"
        $GosecLines += "[!] $($Issues.Count) probleme(s) detecte(s)"
        $Issues | ForEach-Object { $GosecLines += $_; Write-Status "      $_" "Yellow" }
    } else {
        $GosecLines += "[OK] Aucune vulnerabilite detectee."
        Write-Status "  [OK] Aucune vulnerabilite." "Green"
    }
} else { $GosecStatut = "SKIP"; $GosecLines += "[SKIP] gosec non disponible."; Write-Status "  [SKIP] gosec absent." "Yellow" }

$Sections += [PSCustomObject]@{ titre="[1/3] GOSEC"; statut=$GosecStatut; lignes=@($GosecLines | ForEach-Object { [PSCustomObject]@{ texte=$_ } }) }
Write-Status ""

# ===========================================================================
# GOVULNCHECK
# ===========================================================================
Write-Status "  [2/3] GOVULNCHECK - CVE dans les dependances"
$VulnLines  = @()
$VulnStatut = "OK"

if (Test-Path $GovulnExe) {
    $VulnOut  = & $GovulnExe ./... 2>&1
    $VulnHits = $VulnOut | Where-Object { $_ -match "^Vulnerability|^\s+ID:|^\s+More info:" }
    if ($VulnHits.Count -gt 0) {
        $HasErrors = $true; $VulnStatut = "CRITIQUE"
        $VulnLines += "[CRITIQUE] CVE detectes :"
        $VulnHits | ForEach-Object { $VulnLines += $_.Trim(); Write-Status "      $_" "Red" }
    } else {
        $VulnLines += "[OK] Aucun CVE."
        Write-Status "  [OK] Aucun CVE dans les dependances." "Green"
    }
} else { $VulnStatut = "SKIP"; $VulnLines += "[SKIP] govulncheck absent."; Write-Status "  [SKIP] govulncheck absent." "Yellow" }

$Sections += [PSCustomObject]@{ titre="[2/3] GOVULNCHECK"; statut=$VulnStatut; lignes=@($VulnLines | ForEach-Object { [PSCustomObject]@{ texte=$_ } }) }
Write-Status ""

# ===========================================================================
# GITLEAKS
# ===========================================================================
Write-Status "  [3/3] GITLEAKS - Detection de secrets"
$LeaksLines  = @()
$LeaksStatut = "OK"

if (Test-Path $GitleaksExe) {
    $LeaksOut = & $GitleaksExe detect --source . --no-git --exclude-path "vendor" --exclude-path "testdata" 2>&1
    if ($LASTEXITCODE -eq 1) {
        $HasSecrets = $true; $HasErrors = $true; $LeaksStatut = "CRITIQUE"
        $LeaksLines += "[CRITIQUE] Secrets detectes dans le code !"
        Write-Status "  [CRITIQUE] Secrets detectes !" "Red"
    } else {
        $LeaksLines += "[OK] Aucun secret detecte."
        Write-Status "  [OK] Aucun secret." "Green"
    }
} else { $LeaksStatut = "SKIP"; $LeaksLines += "[SKIP] gitleaks absent."; Write-Status "  [SKIP] gitleaks absent." "Yellow" }

$Sections += [PSCustomObject]@{ titre="[3/3] GITLEAKS"; statut=$LeaksStatut; lignes=@($LeaksLines | ForEach-Object { [PSCustomObject]@{ texte=$_ } }) }

Pop-Location

# ===========================================================================
# RESULTAT GLOBAL + RAPPORT TXT
# ===========================================================================
$ResultatGlobal = if ($HasSecrets) { "CRITIQUE" } elseif ($HasErrors) { "AVERTISSEMENT" } else { "OK" }

Write-Status ""
Write-Status "  ============================================================"
if ($HasSecrets)    { Write-Status "  RESULTAT : CRITIQUE" "Red" }
elseif ($HasErrors) { Write-Status "  RESULTAT : AVERTISSEMENT" "Yellow" }
else                { Write-Status "  RESULTAT : OK" "Green" }
Write-Status "  ============================================================"
Write-Status ""

# Rapport TXT (toujours genere)
$TxtLines = @()
$TxtLines += "================================================================"
$TxtLines += "  Velociraptor-IA - Audit Securite IHM"
$TxtLines += "  Date     : $Date"
$TxtLines += "  Resultat : $ResultatGlobal"
$TxtLines += "================================================================"
$TxtLines += ""
foreach ($sec in $Sections) {
    $TxtLines += "----------------------------------------------------------------"
    $TxtLines += "  $($sec.titre)  [Statut: $($sec.statut)]"
    $TxtLines += "----------------------------------------------------------------"
    foreach ($l in $sec.lignes) { $TxtLines += "  $($l.texte)" }
    $TxtLines += ""
}
$TxtLines += "================================================================"
[System.IO.File]::WriteAllLines($TxtFile, $TxtLines, (New-Object System.Text.UTF8Encoding $false))
Write-Status "  [OK] Rapport TXT : $TxtFile" "Green"

# PDF si audit.exe present
if (Test-Path $AuditExe) {
    $JsonReport = [PSCustomObject]@{ date=$Date; project="Velociraptor-IA IHM"; resultat=$ResultatGlobal; sections=$Sections }
    $TmpJson = Join-Path $AuditDir "audit_tmp_$Date.json"
    $JsonReport | ConvertTo-Json -Depth 10 | Out-File $TmpJson -Encoding UTF8
    & $AuditExe -in $TmpJson -out $PdfFile 2>$null
    Remove-Item $TmpJson -Force -ErrorAction SilentlyContinue
    if (Test-Path $PdfFile) { Write-Status "  [OK] Rapport PDF : $PdfFile" "Green" }
} else {
    Write-Status "  [i] audit.exe absent - seul le TXT est genere." "Cyan"
}

if ($HasSecrets) { exit 1 }
exit 0
