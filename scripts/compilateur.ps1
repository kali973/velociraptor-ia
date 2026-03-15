param(
    [string]$Target
)

# ProjectDir = dossier racine du projet (parent de scripts/)
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

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
                Write-Host "  -> Port $Port libere."
            }
        }
    } else {
        Write-Host "  -> Port $Port libre."
    }
}

# ===========================================================================
# DETECTION AUTOMATIQUE D'UNE CLE USB
# ===========================================================================
# Méthode 1 : Get-Disk (la plus fiable sur Windows 10/11)
# Méthode 2 : Get-WmiObject Win32_LogicalDisk DriveType=2 (fallback)
# Méthode 3 : Get-PSDrive + test écriture réelle (fallback ultime)

$UsbDrive = $null

# -- Méthode 1 : Get-Disk (PowerShell 5+ / Windows 10+) ----------------------
try {
    $usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.OperationalStatus -eq 'Online' } -ErrorAction SilentlyContinue
    if ($usbDisks) {
        foreach ($disk in $usbDisks) {
            $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
            foreach ($part in $partitions) {
                $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
                if ($vol -and $vol.DriveLetter) {
                    $UsbDrive = $vol.DriveLetter
                    break
                }
            }
            if ($UsbDrive) { break }
        }
    }
} catch { }

# -- Méthode 2 : WMI DriveType=2 (fallback) -----------------------------------
if (-not $UsbDrive) {
    try {
        $wmiDisks = Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue |
                    Where-Object { $_.DriveType -eq 2 -and $_.DeviceID -ne $null }
        if ($wmiDisks) {
            $first = @($wmiDisks)[0]
            $UsbDrive = $first.DeviceID.TrimEnd(':').TrimEnd('\')
        }
    } catch { }
}

# -- Méthode 3 : Get-PSDrive FileSystem excluant C: et D: (fallback ultime) --
if (-not $UsbDrive) {
    try {
        $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -notin @('C','D') -and $_.Root -match '^[A-Z]:\\$' }
        foreach ($drv in $drives) {
            $letter = $drv.Name
            # Vérifier que c'est bien amovible via WMI sur cette lettre précise
            $info = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue
            if ($info -and ($info.DriveType -eq 2 -or $info.MediaType -eq 11)) {
                $UsbDrive = $letter
                break
            }
            # Fallback : si le volume répond et n'est pas système, on l'accepte
            if (Test-Path "${letter}:\") {
                $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
                if ($vol -and $vol.DriveType -eq 'Removable') {
                    $UsbDrive = $letter
                    break
                }
            }
        }
    } catch { }
}

# -- Résultat détection -------------------------------------------------------
Write-Host ""
if ($UsbDrive) {
    $usbLabel = ""
    try {
        $v = Get-Volume -DriveLetter $UsbDrive -ErrorAction SilentlyContinue
        if ($v -and $v.FileSystemLabel) { $usbLabel = " ($($v.FileSystemLabel))" }
    } catch { }
    Write-Host "  =========================================="
    Write-Host "    CLE USB DETECTEE : ${UsbDrive}:\${usbLabel}"
    Write-Host "    Installation automatique sur la cle."
    Write-Host "  =========================================="
} else {
    Write-Host "  Aucune cle USB detectee -> compilation dans le dossier courant."
    Write-Host "  (Si une cle est branchee, debranchez/rebranchez et relancez bootstrap.bat)"
}
Write-Host ""

$UsbMode = ($null -ne $UsbDrive)


# ===========================================================================
# AUDIT SECURITE DU CODE (avant compilation)
# ===========================================================================

Write-Host ""
Write-Host "=== Audit securite du code source ===" -ForegroundColor Cyan
$AuditScript = Join-Path $ScriptDir "audit_securite.ps1"
if (Test-Path $AuditScript) {
    & powershell -ExecutionPolicy Bypass -File $AuditScript
    if ($LASTEXITCODE -eq 1) {
        Write-Host "" 
        Write-Host "  [!] ATTENTION : Des secrets ont ete detectes dans le code." -ForegroundColor Red
        Write-Host "      Consultez le rapport dans audit\ avant de distribuer." -ForegroundColor Red
        Write-Host ""
        # Non bloquant : on continue la compilation mais on avertit
    } elseif ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Audit securite : aucun secret detecte." -ForegroundColor Green
    }
} else {
    Write-Host "  [i] audit_securite.ps1 absent - audit ignore." -ForegroundColor Yellow
}
Write-Host ""

# ===========================================================================
# CIBLE DE COMPILATION
# ===========================================================================

Write-Host "=== Compilation de RF Sandbox Go ==="

if ($UsbMode) {
    $Target = "windows"
    Write-Host "  -> Mode USB : cible forcee windows/amd64"
} elseif (-not $Target) {
    $Target = Detect-OS
    Write-Host "  -> Cible auto-detectee : $Target"
} else {
    Write-Host "  -> Cible forcee : $Target"
}

switch ($Target.ToLower()) {
    "windows" { $env:GOOS = "windows"; $env:GOARCH = "amd64"; $Ext = ".exe" }
    "linux"   { $env:GOOS = "linux";   $env:GOARCH = "amd64"; $Ext = ""     }
    "darwin"  { $env:GOOS = "darwin";  $env:GOARCH = "amd64"; $Ext = ""     }
    default   { Write-Host "Cible invalide. Utilise : windows, linux ou darwin"; exit 1 }
}

$MainExe  = "rf-sandbox${Ext}"
$VaultExe = "vault${Ext}"

# ===========================================================================
# DEPENDANCES GO
# ===========================================================================

Push-Location $ProjectDir

Write-Host ""
Write-Host "Installation des dependances Go..."

Write-Host "  -> go get github.com/Azure/go-ntlmssp"
go get github.com/Azure/go-ntlmssp@v0.0.0-20221128193559-754e69321358
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : go get go-ntlmssp a echoue"
    Write-Host "  - Verifier la connexion Internet"
    Write-Host "  - Proxy -> essayer : GOPROXY=direct go get ..."
    Pop-Location
    exit 1
}

Write-Host "  -> go get github.com/joho/godotenv"
go get github.com/joho/godotenv@v1.5.1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : go get godotenv a echoue"
    Pop-Location
    exit 1
}

Write-Host "  -> go mod tidy"
go mod tidy
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : go mod tidy a echoue"
    Pop-Location
    exit 1
}

# ===========================================================================
# BUILD
# ===========================================================================

Write-Host ""
Write-Host "Compilation en cours pour $env:GOOS/$env:GOARCH..."

Write-Host "  -> $MainExe"
go build -ldflags="-s -w" -o $MainExe ./cmd
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : compilation de $MainExe echouee."
    Pop-Location
    exit 1
}
Write-Host "  [OK] $MainExe"

Write-Host "  -> $VaultExe"
go build -ldflags="-s -w" -o $VaultExe ./cmd/vault
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR : compilation de $VaultExe echouee."
    Pop-Location
    exit 1
}
Write-Host "  [OK] $VaultExe"

# Compiler audit.exe (generateur PDF rapport securite)
$AuditExePath = Join-Path $ProjectDir "audit${Ext}"
Write-Host "  -> audit${Ext}"
go build -ldflags="-s -w" -o $AuditExePath ./cmd/audit
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] audit${Ext}"
} else {
    Write-Host "  [!] audit${Ext} : compilation echouee (non bloquant)" -ForegroundColor Yellow
}

# Compiler setup-moteur.exe (remplace setup_moteur.ps1 — en Go, sans PowerShell)
$SetupMoteurPath = Join-Path $ProjectDir "setup-moteur${Ext}"
Write-Host "  -> setup-moteur${Ext}"
go build -ldflags="-s -w" -o $SetupMoteurPath ./cmd/setup-moteur
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] setup-moteur${Ext}"
} else {
    Write-Host "  [!] setup-moteur${Ext} : compilation echouee (non bloquant)" -ForegroundColor Yellow
}

# Compiler bootstrap-post.exe (remplace etapes 3+4 de bootstrap.bat — en Go)
$BootstrapPostPath = Join-Path $ProjectDir "bootstrap-post${Ext}"
Write-Host "  -> bootstrap-post${Ext}"
go build -ldflags="-s -w" -o $BootstrapPostPath ./cmd/bootstrap-post
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] bootstrap-post${Ext}"
} else {
    Write-Host "  [!] bootstrap-post${Ext} : compilation echouee (non bloquant)" -ForegroundColor Yellow
}

# Compiler trainer.exe (fine-tuning LoRA Mistral 7B — 100% Go, zéro Python)
# Utilise llama-finetune.exe natif depuis le même zip que llama-server.exe
$TrainerPath = Join-Path $ProjectDir "trainer${Ext}"
Write-Host "  -> trainer${Ext}"
go build -ldflags="-s -w" -o $TrainerPath ./cmd/trainer
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] trainer${Ext} (fine-tuning LoRA — 100% Go, zéro Python)"
} else {
    Write-Host "  [!] trainer${Ext} : compilation echouee (non bloquant)" -ForegroundColor Yellow
}

Pop-Location

Write-Host ""
Write-Host "[OK] Compilation reussie : $MainExe + $VaultExe + audit${Ext} + setup-moteur${Ext} + bootstrap-post${Ext} + trainer${Ext}"

# ===========================================================================
# MODE USB - Copie complete sur la cle
# ===========================================================================

if ($UsbMode) {

    $UsbRoot = "${UsbDrive}:\rf-sandbox-go"

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  Installation sur ${UsbDrive}:\rf-sandbox-go"
    Write-Host "=========================================="

    # Verifier l'espace disponible sur la cle USB
    $mainExeSize  = (Get-Item (Join-Path $ProjectDir $MainExe)).Length
    $vaultExeSize = (Get-Item (Join-Path $ProjectDir $VaultExe)).Length
    $requiredBytes = $mainExeSize + $vaultExeSize + 5MB  # 5 Mo de marge pour config/samples
    $usbDisk = Get-PSDrive -Name $UsbDrive -ErrorAction SilentlyContinue
    if ($null -eq $usbDisk) {
        $usbDisk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='${UsbDrive}:'" -ErrorAction SilentlyContinue
        $freeBytes = if ($usbDisk) { $usbDisk.FreeSpace } else { 0 }
    } else {
        $freeBytes = $usbDisk.Free * 1KB
    }
    if ($freeBytes -lt $requiredBytes) {
        $freeMB     = [math]::Round($freeBytes / 1MB, 1)
        $requiredMB = [math]::Round($requiredBytes / 1MB, 1)
        Write-Host ""
        Write-Host "  [ERREUR] Espace insuffisant sur la cle USB ${UsbDrive}:\" -ForegroundColor Red
        Write-Host "           Disponible : ${freeMB} Mo" -ForegroundColor Red
        Write-Host "           Necessaire : ${requiredMB} Mo" -ForegroundColor Red
        Write-Host "  Liberez de l espace sur la cle et relancez bootstrap.bat." -ForegroundColor Yellow
        Write-Host ""
        pause
        exit 1
    }

    # Creer l'arborescence
    foreach ($sub in @("", "config", "output", "samples")) {
        $d = Join-Path $UsbRoot $sub
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # Executables
    try {
        Copy-Item (Join-Path $ProjectDir $MainExe) (Join-Path $UsbRoot $MainExe) -Force -ErrorAction Stop
        Write-Host "  [OK] $MainExe"
    } catch {
        Write-Host "  [ERREUR] Copie de $MainExe echouee : $_" -ForegroundColor Red
        Write-Host "  Verifiez l espace disponible sur la cle USB." -ForegroundColor Yellow
        pause
        exit 1
    }

    try {
        Copy-Item (Join-Path $ProjectDir $VaultExe) (Join-Path $UsbRoot $VaultExe) -Force -ErrorAction Stop
        Write-Host "  [OK] $VaultExe"
    } catch {
        Write-Host "  [ERREUR] Copie de $VaultExe echouee : $_" -ForegroundColor Red
        Write-Host "  Verifiez l espace disponible sur la cle USB." -ForegroundColor Yellow
        pause
        exit 1
    }

    # config/
    $src = Join-Path $ProjectDir "config"
    if (Test-Path $src) {
        $configDst = Join-Path $UsbRoot "config"
        if (Test-Path $configDst) { Remove-Item $configDst -Recurse -Force }
        New-Item -ItemType Directory -Path $configDst -Force | Out-Null
        Get-ChildItem -Path $src | ForEach-Object { Copy-Item $_.FullName $configDst -Recurse -Force }
        Write-Host "  [OK] config/"
    } else { Write-Host "  [WARN] config/ introuvable" }

    # moteur\ (binaire Ollama + modele Mistral 7B - ~4,1 Go)
    $src = Join-Path $ProjectDir "moteur"
    if (Test-Path $src) {
        $moteurDst = Join-Path $UsbRoot "moteur"
        Write-Host "  Copie du moteur IA (moteur\) vers la cle USB (~4 Go, patience)..."
        if (Test-Path $moteurDst) { Remove-Item $moteurDst -Recurse -Force }
        Copy-Item $src $moteurDst -Recurse -Force
        $moteurSizeMB = [math]::Round((Get-ChildItem $moteurDst -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
        Write-Host "  [OK] moteur\  ($moteurSizeMB Mo)"
    } else {
        Write-Host "  [INFO] moteur\ absent - moteur IA non inclus sur la cle."
        Write-Host "         Sur la machine cible, executer : powershell -File setup_moteur.ps1"
    }

    # samples/
    $src = Join-Path $ProjectDir "samples"
    if (Test-Path $src) {
        $dst = Join-Path $UsbRoot "samples"
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        Get-ChildItem -Path $src | ForEach-Object { Copy-Item $_.FullName $dst -Recurse -Force }
        Write-Host "  [OK] samples/"
    }

    # lancer.bat
    $src = Join-Path $ScriptDir "lancer.bat"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $UsbRoot "lancer.bat") -Force
        Write-Host "  [OK] lancer.bat"
    } else { Write-Host "  [WARN] lancer.bat introuvable dans $ScriptDir" }

    # update_proxy.ps1
    $src = Join-Path $ScriptDir "update_proxy.ps1"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $UsbRoot "update_proxy.ps1") -Force
        Write-Host "  [OK] update_proxy.ps1"
    } else { Write-Host "  [WARN] update_proxy.ps1 introuvable dans $ScriptDir" }

    # setup-moteur.exe (remplace setup_moteur.ps1 — en Go, sans PowerShell)
    $src = Join-Path $ProjectDir "setup-moteur.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $UsbRoot "setup-moteur.exe") -Force
        Write-Host "  [OK] setup-moteur.exe"
    } else { Write-Host "  [WARN] setup-moteur.exe introuvable (recompilez d'abord)" }

    # bootstrap-post.exe (audit + setup moteur en Go)
    $src = Join-Path $ProjectDir "bootstrap-post.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $UsbRoot "bootstrap-post.exe") -Force
        Write-Host "  [OK] bootstrap-post.exe"
    } else { Write-Host "  [WARN] bootstrap-post.exe introuvable (recompilez d'abord)" }

    # trainer.exe (fine-tuning LoRA Mistral 7B — 100% Go, zéro Python)
    $src = Join-Path $ProjectDir "trainer.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $UsbRoot "trainer.exe") -Force
        Write-Host "  [OK] trainer.exe"
    } else { Write-Host "  [WARN] trainer.exe introuvable (recompilez d'abord)" }

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "  Installation terminee !"
    Write-Host "  ${UsbDrive}:\rf-sandbox-go\"
    Write-Host ""
    Write-Host "  Contenu installe :"
    Write-Host "    rf-sandbox.exe      executable principal"
    Write-Host "    vault.exe           gestion des secrets"
    Write-Host "    setup-moteur.exe    telecharge le moteur IA (Go natif)"
    Write-Host "    bootstrap-post.exe  audit + setup moteur (Go natif)"
    Write-Host "    trainer.exe         fine-tuning LoRA Mistral 7B (Go natif)"
    Write-Host "    config\             configuration (token API, proxy)"
    Write-Host "    output\             rapports PDF generes"
    Write-Host "    samples\            fichiers batch exemples"
    Write-Host "    lancer.bat          point d entree (double-clic)"
    Write-Host "    update_proxy.ps1    gestion proxy automatique"
    Write-Host ""
    Write-Host "  MOTEUR IA :"
    $moteurOnUsb = Join-Path $UsbRoot "moteur"
    if (Test-Path $moteurOnUsb) {
        Write-Host "    moteur\  -> Ollama + Mistral 7B inclus (pret hors-ligne)"
    } else {
        Write-Host "    moteur\  -> absent. Sur la machine cible, executer :"
        Write-Host "               powershell -File ${UsbDrive}:\rf-sandbox-go\setup_moteur.ps1"
    }
    Write-Host "=========================================="
    Write-Host ""
    exit 0
}

# ===========================================================================
# MODE NORMAL - Vault et lancement local
# ===========================================================================

$VaultKey = Join-Path $ProjectDir "config\.vault.key"
$vaultExePath = Join-Path $ProjectDir $VaultExe

# vault init est maintenant idempotent : ne regenere pas la cle si elle existe
& $vaultExePath init
if ($LASTEXITCODE -ne 0) { Write-Host "ERREUR : vault init echoue."; exit 1 }

# vault seal : toujours appele pour synchroniser le chiffrement avec la cle courante
Write-Host "Chiffrement/synchronisation du token..."
& $vaultExePath seal
if ($LASTEXITCODE -ne 0) { Write-Host "ERREUR : vault seal echoue."; exit 1 }
& $vaultExePath status

Write-Host ""
Write-Host "Verification du port 8766..."
Kill-Port -Port 8766
Write-Host ""
Write-Host "Lancement sur http://localhost:8766 ..."
$exe = Join-Path $ProjectDir $MainExe
$args_list = @("-ui")
& $exe @args_lis
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbscGsrcSm5crH
# TJLceFZtf/PPWMer8Kq83OIDYOvqAaCCAxIwggMOMIIB9qADAgECAhBJSLcvN+lN
# g0qp7Gck3HUxMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNVBAMMFFJGLVNhbmRib3gt
# TG9jYWxTaWduMB4XDTI2MDMwODIwMTUxMVoXDTM2MDMwODIwMjUxMVowHzEdMBsG
# A1UEAwwUUkYtU2FuZGJveC1Mb2NhbFNpZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQC56Djo765/ka61tSCCtwRDeD6e30ITz1cn/wvjD42Um/JDLNwg
# fJME0ggbr9ctMvktcMgblyN2hShuRmo1xkbCwQlLm1XDEZB3Ai1/nZcPb7zujsVZ
# ZwX92N1nOzV2O90qP5aBP/8NbpSkPkYVKVWvZg1Qy6cv5ZSfgwsfTeDIJTCazRsQ
# ZbWfIRCN0z/frmKVw/OmuNHonUFmiPz/lUaDbiFz27yviRt6Z+NBWtLih69UWR0b
# QV5f3d8on2pzIPuPA7HTN5ICd44KZTfV0B8I8/TSJntVylANxR+FPjdEvG5cLWSY
# bPFo83GpawqNqrzSgupQ4TtiFlMiWMr2ajHlAgMBAAGjRjBEMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUmVd85BqR7Ym7Q1u6
# sh0g6WaH/wEwDQYJKoZIhvcNAQELBQADggEBAEJnNL5jZSBPX7M8kdcoyWYncy/U
# ZlGwFAoSZ/aVOwrzY95dcUihrrP6S+LBSjUT/JAoxvWWPJAAUwzkdl2U7m8v8tPQ
# JQtq1nZfZGNtIgbp+Q1YOp7xsu8dOTaNvxuKO421Hu3CsZju6kjgmUt1d8ba8c/c
# bqh6kc0e1YYC8wTiz9WAt5Kegy7CWLesb6yb1y7aeLHVcpMNlGP/ki2H3MV/+b2i
# R/sdnLV1Ip9OWTWg/zlIC243OXP1S4NIcEYFk3yxXD/8LJIz53IRBJibd5NRHnWP
# Q5Utyndj5a10C2yOPGGkd0jD7v8wDYGFmCGClXQd4DZoqEcq2RPxga5c5LgxggHl
# MIIB4QIBATAzMB8xHTAbBgNVBAMMFFJGLVNhbmRib3gtTG9jYWxTaWduAhBJSLcv
# N+lNg0qp7Gck3HUxMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILjFx1N4l6ky6ES1+MgP
# nBntgbltZm8m1xG3syV1GAjhMA0GCSqGSIb3DQEBAQUABIIBABAvQ8yi5yinezZY
# rkM4p2qbFcyUAveZJvA7RmU/++psP8YnurONFDHjFz9RV0Pn1eJE4QoRLFLRsst4
# 5VDPEVmlpxSKmS21P+i/KCZcamFoxZhpoAcwMGVrHBfjsdqCG0pMWDtqvQxLUldk
# buQH80SJ2mZ0mRnKyTLc+QX8A/FQ+7EIQCXLzm0uuaEbjqGPv9mdXosrF88B/P+u
# G1+1EdNxV/E7DIhHF+quR7kk3JbSH9zujg52z3jFvxYJ4rwomhbpC/58CPQC5XTa
# NOE5yVxwIu6NH39jJ23cv+C7zJP90VwBtOS0wq4+QY3qhgZegtEUSIkEH5WQv6Y4
# oIveouM=
# SIG # End signature block
