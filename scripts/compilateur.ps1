param(
    [string]$Target,
    [switch]$BuildVelociraptor  # passer -BuildVelociraptor pour aussi compiler velociraptor.exe
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$IHMDir     = Join-Path $ScriptDir "ia_forensic"

# ===========================================================================
# FONCTIONS
# ===========================================================================

function Detect-OS {
    if ($IsWindows) { return "windows" }
    elseif ($IsLinux) { return "linux" }
    elseif ($IsMacOS) { return "darwin" }
    else { return "windows" }
}

function Kill-Port {
    param([int]$Port)
    $connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $procPid = $conn.OwningProcess
            $proc    = Get-Process -Id $procPid -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "  -> Port $Port occupe par $($proc.Name) (PID $procPid) -> Kill..."
                Stop-Process -Id $procPid -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500
            }
        }
    } else {
        Write-Host "  -> Port 8767 libre."
    }
}

# ===========================================================================
# DETECTION CLE USB
# ===========================================================================

$UsbDrive = $null
try {
    $usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.OperationalStatus -eq 'Online' } -ErrorAction SilentlyContinue
    if ($usbDisks) {
        foreach ($disk in $usbDisks) {
            $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
            foreach ($part in $partitions) {
                $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
                if ($vol -and $vol.DriveLetter) { $UsbDrive = $vol.DriveLetter; break }
            }
            if ($UsbDrive) { break }
        }
    }
} catch { }

Write-Host ""
if ($UsbDrive) {
    Write-Host "  =========================================="
    Write-Host "    CLE USB DETECTEE : ${UsbDrive}:\"
    Write-Host "    Installation automatique sur la cle."
    Write-Host "  =========================================="
} else {
    Write-Host "  Aucune cle USB detectee -> compilation locale."
}
Write-Host ""
$UsbMode = ($null -ne $UsbDrive)

# ===========================================================================
# AUDIT SECURITE CODE SOURCE IHM
# ===========================================================================

Write-Host ""
Write-Host "=== Audit securite du code source IHM ===" -ForegroundColor Cyan
$AuditScript = Join-Path $ScriptDir "audit_securite.ps1"
if (Test-Path $AuditScript) {
    & powershell -ExecutionPolicy Bypass -File $AuditScript
    if ($LASTEXITCODE -eq 1) {
        Write-Host "  [!] ATTENTION : Des secrets detectes dans le code." -ForegroundColor Red
    } elseif ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Audit securite : OK" -ForegroundColor Green
    } else {
        # LASTEXITCODE=2 ou autre = avertissements CVE stdlib Go (non bloquants)
        Write-Host "  [!] Audit : avertissements detectes (voir audit\)." -ForegroundColor Yellow
        Write-Host "      Les CVE Go stdlib se corrigent en mettant a jour Go >= 1.25.8 :" -ForegroundColor Yellow
        Write-Host "      https://golang.org/dl/" -ForegroundColor Cyan
    }
} else {
    Write-Host "  [i] audit_securite.ps1 absent - audit ignore." -ForegroundColor Yellow
}
Write-Host ""

# ===========================================================================
# CIBLE
# ===========================================================================

Write-Host "=== Compilation Velociraptor-IA ==="

if ($UsbMode) {
    $Target = "windows"
    Write-Host "  -> Mode USB : cible forcee windows/amd64"
} elseif (-not $Target) {
    $Target = Detect-OS
    Write-Host "  -> Cible auto-detectee : $Target"
}

switch ($Target.ToLower()) {
    "windows" { $env:GOOS = "windows"; $env:GOARCH = "amd64"; $Ext = ".exe" }
    "linux"   { $env:GOOS = "linux";   $env:GOARCH = "amd64"; $Ext = ""     }
    "darwin"  { $env:GOOS = "darwin";  $env:GOARCH = "amd64"; $Ext = ""     }
    default   { Write-Host "Cible invalide : $Target"; exit 1 }
}

$IHMExe = "ia_forensic${Ext}"

# ===========================================================================
# DEPENDANCES IHM
# ===========================================================================

Push-Location $IHMDir

Write-Host ""
Write-Host "Installation des dependances IHM (ia_forensic/)..."

Write-Host "  -> go get github.com/mattn/go-sqlite3"
go get github.com/mattn/go-sqlite3@v1.14.34
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : go get go-sqlite3 echoue (GCC requis dans le PATH)" -ForegroundColor Red
    Pop-Location; exit 1
}

Write-Host "  -> go mod tidy"
go mod tidy
if ($LASTEXITCODE -ne 0) { Write-Host "ERREUR : go mod tidy echoue"; Pop-Location; exit 1 }

# ===========================================================================
# BUILD IHM
# ===========================================================================

Write-Host ""
Write-Host "Compilation IHM ia_forensic..."

$IHMOut = Join-Path $ScriptDir $IHMExe
go build -ldflags="-s -w" -o $IHMOut .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : compilation IHM echouee. Verifiez GCC dans le PATH." -ForegroundColor Red
    Pop-Location; exit 1
}
Write-Host "  [OK] $IHMExe" -ForegroundColor Green

Pop-Location

# ===========================================================================
# BUILD VELOCIRAPTOR (optionnel ou si USB)
# ===========================================================================

if ($BuildVelociraptor -or $UsbMode) {
    Write-Host ""
    Write-Host "=== Compilation Velociraptor (make windows) ==="
    Write-Host "  Cela peut prendre 5-15 minutes (compilation complete du moteur DFIR)..."
    Push-Location $ProjectDir

    # Verifier que make est disponible
    $makeCmd = Get-Command "make" -ErrorAction SilentlyContinue
    if (-not $makeCmd) {
        Write-Host "  [!] 'make' introuvable. Installez MinGW-w64 ou Chocolatey (choco install make)." -ForegroundColor Yellow
        Write-Host "  [i] Velociraptor non compile. Telechargez le binaire depuis :" -ForegroundColor Cyan
        Write-Host "      https://github.com/Velocidex/velociraptor/releases" -ForegroundColor Cyan
        Pop-Location
    } else {
        # Installer les deps GUI Node.js si necessaire
        $guiDir = Join-Path $ProjectDir "gui\velociraptor"
        if ((Test-Path $guiDir) -and -not (Test-Path (Join-Path $guiDir "node_modules"))) {
            Write-Host "  -> npm install (GUI Velociraptor)..."
            Push-Location $guiDir
            npm install 2>&1 | Out-Null
            Pop-Location
        }

        make windows
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] velociraptor-windows-amd64.exe compile." -ForegroundColor Green
        } else {
            Write-Host "  [!] make windows echoue (non bloquant)." -ForegroundColor Yellow
        }
        Pop-Location
    }
}

Write-Host ""
Write-Host "[OK] Compilation reussie : $IHMExe" -ForegroundColor Green
Write-Host ""
Write-Host "  Pour lancer l IHM : double-cliquer sur lancer.bat" -ForegroundColor Cyan
Write-Host "  ou executer : .\lancer.bat" -ForegroundColor Cyan
Write-Host ""


if ($UsbMode) {
    $UsbRoot = "${UsbDrive}:\velociraptor-ia"
    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  Installation sur ${UsbDrive}:\velociraptor-ia"
    Write-Host "=========================================="

    foreach ($sub in @("", "config", "collections", "reports", "moteur\models", "scripts")) {
        $d = Join-Path $UsbRoot $sub
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # IHM exe
    Copy-Item (Join-Path $ScriptDir $IHMExe) (Join-Path $UsbRoot $IHMExe) -Force
    Write-Host "  [OK] $IHMExe"

    # Velociraptor exe si present
    $veloExe = Join-Path $ProjectDir "velociraptor-windows-amd64.exe"
    if (Test-Path $veloExe) {
        Copy-Item $veloExe (Join-Path $UsbRoot "velociraptor.exe") -Force
        Write-Host "  [OK] velociraptor.exe"
    } else {
        Write-Host "  [INFO] velociraptor.exe absent - telechargez-le depuis GitHub Releases"
    }

    # Config
    $src = Join-Path $ProjectDir "config"
    if (Test-Path $src) {
        Get-ChildItem -Path $src | ForEach-Object { Copy-Item $_.FullName (Join-Path $UsbRoot "config") -Recurse -Force }
        Write-Host "  [OK] config\"
    }

    # Scripts
    Get-ChildItem -Path $ScriptDir -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $UsbRoot "scripts") -Force
    }
    Write-Host "  [OK] scripts\"

    # Lancer.bat a la racine
    Copy-Item (Join-Path $ScriptDir "lancer.bat") (Join-Path $UsbRoot "lancer.bat") -Force
    Write-Host "  [OK] lancer.bat"

    # Moteur IA si present
    $moteurSrc = Join-Path (Split-Path -Parent $ProjectDir) "moteur"
    if (Test-Path $moteurSrc) {
        Write-Host "  Copie du moteur IA (~12 Go, patience)..."
        Copy-Item $moteurSrc (Join-Path $UsbRoot "moteur") -Recurse -Force
        Write-Host "  [OK] moteur\"
    } else {
        Write-Host "  [INFO] moteur\ absent - lancez scripts\setup_moteur.ps1 sur la machine cible"
    }

    Write-Host ""
    Write-Host "  Installation terminee : ${UsbDrive}:\velociraptor-ia\"
    exit 0
}

# ===========================================================================
# MODE LOCAL - Lancement direct de l IHM
# compilateur.ps1 lance lancer.bat directement pour eviter la chaine
# bootstrap -> compilateur -> bootstrap -> lancer qui cause des double-lancements
# ===========================================================================

Write-Host ""
Write-Host "=========================================="
Write-Host "  Compilation terminee avec succes !"
Write-Host "  $IHMExe disponible dans : $ScriptDir"
Write-Host "=========================================="
Write-Host ""
Write-Host "  Lancement de l IHM..." -ForegroundColor Cyan

$LancerBat = Join-Path $ScriptDir "lancer.bat"
if (Test-Path $LancerBat) {
    # Lancer lancer.bat dans la meme fenetre cmd (bloquant)
    # On utilise cmd /c pour eviter les problemes de chemin avec espaces
    $proc = Start-Process -FilePath "cmd.exe" `
        -ArgumentList "/c `"$LancerBat`"" `
        -Wait -PassThru -NoNewWindow
    exit $proc.ExitCode
} else {
    Write-Host "  [!] lancer.bat introuvable dans $ScriptDir" -ForegroundColor Yellow
    exit 0
}
