# =============================================================================
# setup_moteur.ps1 - Telecharge llama.cpp + Mistral 7B GGUF dans moteur\
#
# IDEMPOTENT : si moteur\ est deja complet, aucun telechargement n'est effectue.
# La verification se fait sur les fichiers reels ? pas de re-download si present.
#
# Structure cible :
#   GolandProjects\
#     moteur\
#       llama-server.exe              <- moteur IA (llama.cpp b8185)
#     cudart64_12.dll + autres DLL  <- CUDA runtime
#     models\
#       mistral-7b-instruct-v0.2.Q4_K_M.gguf  (~4.1 Go)
# =============================================================================

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir   = Split-Path -Parent $ScriptDir
$WorkspaceDir = Split-Path -Parent $ProjectDir
$MoteurDir    = Join-Path $WorkspaceDir "moteur"
$ModelsDir  = Join-Path $MoteurDir "models"
$LlamaExe   = Join-Path $MoteurDir "llama-server.exe"
$ModelFile  = Join-Path $ModelsDir "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
$ModelMinSize = 100MB

# URLs llama.cpp b8185 (2026-03-02) - GitHub Releases
$UrlCUDA   = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cuda-cu12.4-x64.zip"
$UrlCUDArt = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/cudart-llama-bin-win-cuda-12.4-x64.zip"
$UrlCPU    = "https://github.com/ggml-org/llama.cpp/releases/download/b8185/llama-b8185-bin-win-cpu-x64.zip"

# Mistral 7B Q4_K_M - Hugging Face
$ModelURL  = "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf"

# =============================================================================
# VERIFICATION RAPIDE - si tout est present, on sort immediatement
# =============================================================================

$LlamaOk = (Test-Path $LlamaExe)
$ModelOk  = (Test-Path $ModelFile) -and ((Get-Item $ModelFile -ErrorAction SilentlyContinue).Length -gt $ModelMinSize)

if ($LlamaOk -and $ModelOk) {
    $SizeMo = [math]::Round((Get-Item $ModelFile).Length / 1MB)
    Write-Host "  [OK] Moteur IA deja pret (llama-server.exe + modele $SizeMo Mo) ? aucun telechargement necessaire."
    exit 0
}

# =============================================================================
# SETUP NECESSAIRE
# =============================================================================

Write-Host ""
Write-Host "  =============================================="
Write-Host "    RF Sandbox Go - Setup moteur IA (llama.cpp)"
Write-Host "  =============================================="
Write-Host "  Moteur  : llama.cpp b8185 + GPU CUDA (partage entre projets)"
Write-Host "  Modele  : Mistral 7B Q4_K_M (~4.1 Go)"
Write-Host "  Workspace : $WorkspaceDir
  Dossier : $MoteurDir"
Write-Host ""

New-Item -ItemType Directory -Path $MoteurDir -Force | Out-Null
New-Item -ItemType Directory -Path $ModelsDir -Force | Out-Null

# =============================================================================
# ETAPE 1 - llama-server.exe (seulement si absent)
# =============================================================================

if ($LlamaOk) {
    Write-Host "  [OK] llama-server.exe deja present ? etape ignoree."
} else {
    $ZipPath    = Join-Path $MoteurDir "llama-cpp.zip"
    $ExtractDir = Join-Path $MoteurDir "llama-extract"
    $Downloaded = $false

    # Tentative CUDA
    Write-Host "  [1/2] Telechargement llama.cpp CUDA (GPU NVIDIA) b8185..."
    try {
        Invoke-WebRequest -Uri $UrlCUDA -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
        Remove-Item $ZipPath -ErrorAction SilentlyContinue
        $Downloaded = $true
        Write-Host "  [OK] Build CUDA telecharge."
    } catch {
        Write-Host "  [!] CUDA indisponible : $($_.Exception.Message)"
        Remove-Item $ZipPath -ErrorAction SilentlyContinue
    }

    # Fallback CPU
    if (-not $Downloaded) {
        Write-Host "  [1/2] Fallback : telechargement llama.cpp CPU b8185..."
        try {
            Invoke-WebRequest -Uri $UrlCPU -OutFile $ZipPath -UseBasicParsing
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
            Remove-Item $ZipPath -ErrorAction SilentlyContinue
            $Downloaded = $true
            Write-Host "  [OK] Build CPU telecharge."
        } catch {
            Write-Host "  [ERREUR] Impossible de telecharger llama.cpp : $($_.Exception.Message)"
            Remove-Item $ExtractDir -Recurse -ErrorAction SilentlyContinue
            exit 1
        }
    }

    # Copier llama-server.exe + DLLs
    $ServerExe = Get-ChildItem -Path $ExtractDir -Recurse -Filter "llama-server.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ServerExe) {
        Write-Host "  [ERREUR] llama-server.exe introuvable dans le zip."
        Remove-Item $ExtractDir -Recurse -ErrorAction SilentlyContinue
        exit 1
    }
    $SrcDir = $ServerExe.DirectoryName
    Get-ChildItem -Path $SrcDir | Where-Object { $_.Extension -in @(".exe", ".dll") } | ForEach-Object {
        Copy-Item $_.FullName $MoteurDir -Force
    }
    Remove-Item $ExtractDir -Recurse -ErrorAction SilentlyContinue

    if (-not (Test-Path $LlamaExe)) {
        Write-Host "  [ERREUR] llama-server.exe non trouve apres extraction."
        exit 1
    }
    Write-Host "  [OK] llama-server.exe installe dans moteur\"

    # DLLs CUDA runtime (cudart64, cublas64...) ? seulement si pas deja presentes
    $DllCount = (Get-ChildItem -Path $MoteurDir -Filter "cudart64*.dll" -ErrorAction SilentlyContinue).Count
    if ($DllCount -eq 0) {
        Write-Host "  Telechargement DLLs CUDA runtime..."
        $CudartZip = Join-Path $MoteurDir "cudart.zip"
        $CudartDir = Join-Path $MoteurDir "cudart-extract"
        try {
            Invoke-WebRequest -Uri $UrlCUDArt -OutFile $CudartZip -UseBasicParsing
            Expand-Archive -Path $CudartZip -DestinationPath $CudartDir -Force
            Remove-Item $CudartZip -ErrorAction SilentlyContinue
            Get-ChildItem -Path $CudartDir -Recurse -Filter "*.dll" | ForEach-Object {
                Copy-Item $_.FullName $MoteurDir -Force
            }
            Remove-Item $CudartDir -Recurse -ErrorAction SilentlyContinue
            $DllCount = (Get-ChildItem -Path $MoteurDir -Filter "*.dll").Count
            Write-Host "  [OK] DLLs CUDA runtime installes ($DllCount fichiers .dll)"
        } catch {
            Write-Host "  [!] DLLs CUDA runtime non telecharges (optionnel si CUDA Toolkit installe)"
        }
    } else {
        Write-Host "  [OK] DLLs CUDA runtime deja presentes ? etape ignoree."
    }
}

# =============================================================================
# ETAPE 2 - Modele GGUF (seulement si absent ou incomplet)
# =============================================================================

if ($ModelOk) {
    $SizeMo = [math]::Round((Get-Item $ModelFile).Length / 1MB)
    Write-Host "  [OK] Modele Mistral 7B deja present ($SizeMo Mo) ? etape ignoree."
} else {
    # Supprimer fichier partiel si present
    if (Test-Path $ModelFile) {
        $PartialSize = [math]::Round((Get-Item $ModelFile).Length / 1MB)
        Write-Host "  [!] Modele partiel detecte ($PartialSize Mo) ? suppression et re-telechargement."
        Remove-Item $ModelFile -Force
    }

    Write-Host "  [2/2] Telechargement Mistral 7B Q4_K_M depuis Hugging Face (~4.1 Go)..."
    Write-Host "        Cela peut prendre plusieurs minutes selon votre connexion."
    Write-Host ""
    $StartTime = Get-Date
    try {
        Invoke-WebRequest -Uri $ModelURL -OutFile $ModelFile -UseBasicParsing
        $Duration = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
        $SizeMo   = [math]::Round((Get-Item $ModelFile).Length / 1MB)
        Write-Host "  [OK] Modele telecharge : $SizeMo Mo en $Duration min."
    } catch {
        Remove-Item $ModelFile -ErrorAction SilentlyContinue
        Write-Host "  [ERREUR] Telechargement echoue : $($_.Exception.Message)"
        Write-Host ""
        Write-Host "  Telechargez manuellement depuis :"
        Write-Host "  $ModelURL"
        Write-Host "  Placez le fichier dans : $ModelsDir"
        exit 1
    }
}

# =============================================================================
# ETAPE 3 - Detection GPU et rapport de configuration
# =============================================================================

Write-Host ""
Write-Host "  [3/3] Detection GPU et configuration optimale..."
Write-Host ""

$GPUDetected = $false
$GPUName     = "Aucun GPU detecte"
$GPUVram     = 0

# Tentative via nvidia-smi (la plus fiable)
try {
    $NvidiaSMI = Get-Command "nvidia-smi" -ErrorAction SilentlyContinue
    if ($NvidiaSMI) {
        $GpuInfo = & nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits 2>$null
        if ($GpuInfo) {
            $Parts = $GpuInfo -split ","
            if ($Parts.Count -ge 2) {
                $GPUName     = $Parts[0].Trim()
                $GPUVram     = [int]($Parts[1].Trim()) / 1024  # Mo -> Go
                $GPUDetected = $true
            }
        }
    }
} catch {}

# Tentative via WMI (Windows uniquement, sans nvidia-smi)
if (-not $GPUDetected) {
    try {
        $WmiGPU = Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -match "NVIDIA|AMD|Radeon|GeForce|RTX|GTX|RX " } |
                  Select-Object -First 1
        if ($WmiGPU) {
            $GPUName     = $WmiGPU.Name
            $GPUVram     = [math]::Round($WmiGPU.AdapterRAM / 1GB, 1)
            $GPUDetected = $true
        }
    } catch {}
}

# Tentative via DLLs CUDA dans moteur/
if (-not $GPUDetected) {
    $CudaDlls = (Get-ChildItem -Path $MoteurDir -Filter "cudart64*.dll" -ErrorAction SilentlyContinue).Count
    if ($CudaDlls -gt 0) {
        $GPUDetected = $true
        $GPUName     = "GPU NVIDIA (DLLs CUDA presentes, nvidia-smi indisponible)"
    }
}

# Calcul du nombre optimal de threads CPU
$CPUCount   = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
$OptThreads = [math]::Max(2, [math]::Min(16, [math]::Floor($CPUCount / 2)))

if ($GPUDetected) {
    Write-Host "  [GPU] Detecte    : $GPUName" -ForegroundColor Green
    if ($GPUVram -gt 0) {
        Write-Host "  [GPU] VRAM       : $([math]::Round($GPUVram, 1)) Go" -ForegroundColor Green
    }
    Write-Host "  [GPU] Config     : -ngl 99 (toutes couches GPU) | --batch-size 512" -ForegroundColor Green
    Write-Host "  [CPU] Threads    : $OptThreads / $CPUCount logiques (reduit car GPU actif)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  NOTE : Le moteur IA utilisera votre GPU au maximum pour des" -ForegroundColor Yellow
    Write-Host "         performances optimales (inference acceleree CUDA)." -ForegroundColor Yellow
} else {
    Write-Host "  [GPU] Aucun GPU NVIDIA detecte — mode CPU uniquement" -ForegroundColor Yellow
    Write-Host "  [CPU] Threads    : $OptThreads / $CPUCount logiques" -ForegroundColor Cyan
    Write-Host "  [CPU] Batch size : 256" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  CONSEIL : Pour de meilleures performances, installez les drivers NVIDIA" -ForegroundColor Yellow
    Write-Host "            et relancez bootstrap.bat pour activer l acceleration GPU." -ForegroundColor Yellow
}

# =============================================================================
# CONFIRMATION FINALE
# =============================================================================

Write-Host ""
Write-Host "  [OK] Moteur IA pret. Demarrage automatique au prochain lancement."
Write-Host ""
