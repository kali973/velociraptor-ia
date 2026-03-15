# ============================================================
#  Signature numerique d'un fichier PowerShell
#  Usage : .\signer.ps1 [-FileToSign <chemin.ps1>]
# ============================================================
param(
    [string]$FileToSign = ""
)

Write-Host "=== Signature numerique de $(Split-Path $FileToSign -Leaf) ===" -ForegroundColor Cyan

if ($FileToSign -eq "" -or -not (Test-Path $FileToSign)) {
    Write-Host "ERREUR : fichier introuvable : $FileToSign" -ForegroundColor Red
    exit 1
}

$CertSubject  = "CN=RF-Sandbox-LocalSign"
# IMPORTANT : on travaille EXCLUSIVEMENT dans CurrentUser\My.
# Cert:\LocalMachine\My stocke la cle privee dans un repertoire systeme
# (C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys) dont les ACL
# interdisent la lecture a un utilisateur non-Admin, meme si HasPrivateKey=True.
# Set-AuthenticodeSignature retourne alors "UnknownError" car CryptSignMessage()
# echoue en silence. La solution est de toujours signer depuis CurrentUser\My.
$SigningStore = "Cert:\CurrentUser\My"

#  Etape 1 : Recherche ou creation du certificat 
Write-Host "Etape 1 : Recherche d'un certificat existant dans CurrentUser\My..."

$cert = Get-ChildItem $SigningStore `
    | Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey } `
    | Sort-Object NotAfter -Descending `
    | Select-Object -First 1

if ($cert) {
    Write-Host "  -> Certificat existant trouve : $($cert.Thumbprint)"

    # Verification que la cle privee est vraiment utilisable
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($null -eq $rsa) { throw "GetRSAPrivateKey retourne null" }
        Write-Host "  -> Cle privee accessible : OK"
    } catch {
        Write-Host "  -> Cle privee inaccessible ($_ ), recreation du certificat..." -ForegroundColor Yellow
        $cert = $null
    }
}

if (-not $cert) {
    Write-Host "  -> Creation d'un nouveau certificat dans CurrentUser\My..."
    $cert = New-SelfSignedCertificate `
        -Subject        $CertSubject `
        -CertStoreLocation $SigningStore `
        -KeyUsage       DigitalSignature `
        -Type           CodeSigningCert `
        -HashAlgorithm  SHA256 `
        -NotAfter       (Get-Date).AddYears(10)

    if (-not $cert) {
        Write-Host "ERREUR : impossible de creer le certificat." -ForegroundColor Red
        exit 1
    }
    Write-Host "  -> Certificat cree : $($cert.Thumbprint)"
}

#  Etape 2 : Installation dans les stores de confiance 
Write-Host "Etape 2 : Installation dans les stores de confiance..."

function Install-CertIfMissing {
    param([string]$StoreName, [string]$StoreScope)
    $path     = "Cert:\$StoreScope\$StoreName"
    $existing = Get-ChildItem $path -ErrorAction SilentlyContinue `
                | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($existing) {
        Write-Host "  -> Deja present dans $StoreScope\$StoreName"
        return
    }
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreScope)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($cert)
        $store.Close()
        Write-Host "  -> Installe dans $StoreScope\$StoreName"
    } catch {
        Write-Host "  -> AVERTISSEMENT : $StoreScope\$StoreName inaccessible (relancer en Admin) : $_" -ForegroundColor Yellow
    }
}

# Tenter les stores machine (necessite Admin) puis les stores utilisateur
Install-CertIfMissing "TrustedPublisher" "LocalMachine"
Install-CertIfMissing "Root"             "LocalMachine"
Install-CertIfMissing "TrustedPublisher" "CurrentUser"
Install-CertIfMissing "Root"             "CurrentUser"

#  Etape 3 : Signature du fichier 
Write-Host "Etape 3 : Signature de $(Split-Path $FileToSign -Leaf) ..."

$result = Set-AuthenticodeSignature `
    -FilePath      $FileToSign `
    -Certificate   $cert `
    -HashAlgorithm SHA256

if ($result.Status -ne "Valid") {
    Write-Host "  -> ERREUR de signature : $($result.Status)" -ForegroundColor Red
    Write-Host "  -> Message             : $($result.StatusMessage)" -ForegroundColor Red
    exit 1
}
Write-Host "  -> Signature reussie ! Statut : $($result.Status)"

#  Etape 4 : Verification 
Write-Host "Etape 4 : Verification de la signature..."

$check = Get-AuthenticodeSignature -FilePath $FileToSign
Write-Host "  -> Fichier  : $($check.Path)"
Write-Host "  -> Statut   : $($check.Status)"
Write-Host "  -> Signe par: $($check.SignerCertificate.Subject)"

if ($check.Status -ne "Valid") {
    Write-Host "ERREUR : verification echouee." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  $(Split-Path $FileToSign -Leaf) est maintenant signe." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green