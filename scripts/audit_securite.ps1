# =============================================================================
# audit_securite.ps1 - Audit securite Velociraptor-IA IHM
# Outils : gosec | govulncheck | gitleaks
# Sortie  : audit\rapport_securite_<date>.txt + .pdf
# =============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$IHMDir      = Join-Path $ScriptDir "ia_forensic"
$ProjectDir  = Split-Path -Parent $ScriptDir
$AuditDir    = Join-Path $ProjectDir "audit"
$Date        = Get-Date -Format "yyyy-MM-dd_HH-mm"
$TxtFile     = Join-Path $AuditDir "rapport_securite_$Date.txt"
$PdfFile     = Join-Path $AuditDir "rapport_securite_$Date.pdf"

$GoPath      = if ($env:GOPATH) { $env:GOPATH } else { Join-Path $env:USERPROFILE "go" }
$GoBin       = Join-Path $GoPath "bin"
$GosecExe    = Join-Path $GoBin "gosec.exe"
$GovulnExe   = Join-Path $GoBin "govulncheck.exe"
$GitleaksDir = Join-Path $ProjectDir "tools"
$GitleaksExe = Join-Path $GitleaksDir "gitleaks.exe"
$GitleaksURL = "https://github.com/gitleaks/gitleaks/releases/download/v8.23.3/gitleaks_8.23.3_windows_x64.zip"

New-Item -ItemType Directory -Path $AuditDir    -Force | Out-Null
New-Item -ItemType Directory -Path $GitleaksDir -Force | Out-Null

# Garder 3 rapports max
Get-ChildItem -Path $AuditDir -Filter "rapport_securite_*.txt" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
Get-ChildItem -Path $AuditDir -Filter "rapport_securite_*.pdf" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

$HasErrors  = $false
$HasSecrets = $false
$Sections   = @()

# Fonction Write-Status avec couleur robuste
function Write-Status {
    param(
        [string]$Line  = "",
        [string]$Color = "White"
    )
    # Valider la couleur pour eviter l'erreur ParameterBindingException
    $validColors = @("Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta",
                     "DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red",
                     "Magenta","Yellow","White")
    if ($validColors -notcontains $Color) { $Color = "White" }
    Write-Host $Line -ForegroundColor $Color
}

Write-Status ""
Write-Status "  ============================================================"
Write-Status "    Velociraptor-IA - Audit Securite IHM"
Write-Status "    Date   : $Date"
Write-Status "    Cible  : scripts\ia_forensic\"
Write-Status "  ============================================================"
Write-Status ""

Push-Location $IHMDir

# ===========================================================================
# INSTALLATION DES OUTILS
# ===========================================================================
Write-Status "  Verification des outils..."

if (-not (Test-Path $GosecExe)) {
    Write-Status "  -> Installation gosec..."
    go install github.com/securego/gosec/v2/cmd/gosec@latest 2>&1 | Out-Null
    if (Test-Path $GosecExe) {
        Write-Status "  [OK] gosec installe." "Green"
    } else {
        Write-Status "  [!] gosec indisponible." "Yellow"
    }
} else {
    Write-Status "  [OK] gosec."
}

if (-not (Test-Path $GovulnExe)) {
    Write-Status "  -> Installation govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest 2>&1 | Out-Null
    if (Test-Path $GovulnExe) {
        Write-Status "  [OK] govulncheck installe." "Green"
    } else {
        Write-Status "  [!] govulncheck indisponible." "Yellow"
    }
} else {
    Write-Status "  [OK] govulncheck."
}

if (-not (Test-Path $GitleaksExe)) {
    Write-Status "  -> Telechargement gitleaks..."
    $zp = Join-Path $GitleaksDir "gl.zip"
    try {
        Invoke-WebRequest -Uri $GitleaksURL -OutFile $zp -UseBasicParsing
        Expand-Archive -Path $zp -DestinationPath $GitleaksDir -Force
        Remove-Item $zp -ErrorAction SilentlyContinue
        if (Test-Path $GitleaksExe) {
            Write-Status "  [OK] gitleaks installe." "Green"
        }
    } catch {
        Write-Status "  [!] gitleaks indisponible." "Yellow"
    }
} else {
    Write-Status "  [OK] gitleaks."
}

Write-Status ""

# ===========================================================================
# AUDIT 1 - GOSEC
# ===========================================================================
Write-Status "  ============================================================"
Write-Status "  [1/3] GOSEC - Analyse statique du code Go"
Write-Status "  ============================================================"

$gosecLines  = @()
$gosecLines  += "[1/3] GOSEC - Analyse statique du code Go (ia_forensic/)"
$gosecStatut = "OK"

if (Test-Path $GosecExe) {
    $raw = & $GosecExe -fmt text -severity medium -confidence medium -exclude G304,G107 ./... 2>&1
    $issues  = @()
    $curBlk  = @()
    foreach ($ln in $raw) {
        if ($ln -match "^\[G\d+\]") {
            if ($curBlk.Count -gt 0) { $issues += ($curBlk -join " | ") }
            $curBlk = @($ln.Trim())
        } elseif ($curBlk.Count -gt 0 -and ($ln -match "Severity:|CWE:|Details:|\s+>")) {
            $curBlk += $ln.Trim()
        } elseif ($curBlk.Count -gt 0 -and $ln.Trim() -eq "") {
            $issues += ($curBlk -join " | ")
            $curBlk = @()
        }
    }
    if ($curBlk.Count -gt 0) { $issues += ($curBlk -join " | ") }

    if ($issues.Count -gt 0) {
        $HasErrors   = $true
        $gosecStatut = "WARN"
        $gosecLines += "[!] $($issues.Count) probleme(s) detecte(s) (exclus : G304, G107)"
        foreach ($iss in $issues) {
            $gosecLines += "  $iss"
            Write-Status "    $iss" "Yellow"
        }
    } else {
        $gosecLines += "[OK] Aucune vulnerabilite detectee."
        Write-Status "  [OK] Aucune vulnerabilite." "Green"
    }
    $raw | Where-Object { $_ -match "^Summary" } | Select-Object -First 1 |
        ForEach-Object { $gosecLines += "  $($_.Trim())" }
    $gosecLines += ""
    $gosecLines += "  Regles exclues : G304 (chemins controles), G107 (URLs configurables)"
} else {
    $gosecStatut = "SKIP"
    $gosecLines += "[SKIP] gosec non disponible."
    Write-Status "  [SKIP] gosec absent." "Yellow"
}

$Sections += [PSCustomObject]@{
    titre  = "[1/3] GOSEC - Analyse statique"
    statut = $gosecStatut
    lignes = $gosecLines
}
Write-Status ""

# ===========================================================================
# AUDIT 2 - GOVULNCHECK
# ===========================================================================
Write-Status "  ============================================================"
Write-Status "  [2/3] GOVULNCHECK - CVE dans les dependances"
Write-Status "  ============================================================"

$vulnLines  = @()
$vulnLines  += "[2/3] GOVULNCHECK - CVE dans les dependances (go.mod)"
$vulnStatut = "OK"

if (Test-Path $GovulnExe) {
    $vo   = & $GovulnExe ./... 2>&1
    $hits = $vo | Where-Object { $_ -match "^Vulnerability|^\s+ID:|^\s+More info:|^\s+Fixed in:" }
    if ($hits.Count -gt 0) {
        $HasErrors  = $true
        $vulnStatut = "CRITIQUE"
        $vulnLines += "[CRITIQUE] CVE detectes dans les dependances :"
        foreach ($v in $hits) {
            $vulnLines += "  $($v.Trim())"
            Write-Status "    $v" "Red"
        }
        $vulnLines += "  Action : go get -u ./... && go mod tidy"
    } else {
        $vulnLines += "[OK] Aucun CVE detecte dans les dependances."
        Write-Status "  [OK] Aucun CVE." "Green"
        $vo | Where-Object { $_ -match "No vulnerabilities|packages" } | Select-Object -First 1 |
            ForEach-Object { $vulnLines += "  $($_.Trim())" }
    }
} else {
    $vulnStatut = "SKIP"
    $vulnLines += "[SKIP] govulncheck non disponible."
    Write-Status "  [SKIP] govulncheck absent." "Yellow"
}

$Sections += [PSCustomObject]@{
    titre  = "[2/3] GOVULNCHECK - CVE dependances"
    statut = $vulnStatut
    lignes = $vulnLines
}
Write-Status ""

# ===========================================================================
# AUDIT 3 - GITLEAKS
# ===========================================================================
Write-Status "  ============================================================"
Write-Status "  [3/3] GITLEAKS - Detection de secrets dans le code"
Write-Status "  ============================================================"

$leaksLines  = @()
$leaksLines  += "[3/3] GITLEAKS - Detection de secrets dans le code source"
$leaksStatut = "OK"

if (Test-Path $GitleaksExe) {
    $lo = & $GitleaksExe detect --source . --no-git `
        --exclude-path "vendor" --exclude-path "config" 2>&1
    $findings = @()
    $cf = @()
    foreach ($ln in $lo) {
        if ($ln -match "^Finding:") {
            $cf = @($ln.Trim())
        } elseif ($cf.Count -gt 0 -and $ln -match "^\s+(Secret|File|Line|RuleID):") {
            $cf += $ln.Trim()
        } elseif ($cf.Count -gt 0 -and $ln.Trim() -eq "") {
            $findings += ($cf -join " | ")
            $cf = @()
        }
    }
    if ($cf.Count -gt 0) { $findings += ($cf -join " | ") }

    if ($LASTEXITCODE -eq 1 -or $findings.Count -gt 0) {
        $HasSecrets  = $true
        $HasErrors   = $true
        $leaksStatut = "CRITIQUE"
        $leaksLines += "[CRITIQUE] $($findings.Count) secret(s) detecte(s) !"
        foreach ($fi in $findings) {
            $leaksLines += "  $fi"
            Write-Status "    $fi" "Red"
        }
        $leaksLines += "  ACTION OBLIGATOIRE : supprimer avant tout commit !"
    } else {
        $leaksLines += "[OK] Aucun secret detecte dans le code source."
        $leaksLines += "  Fichiers exclus : config/ (gitignore)"
        Write-Status "  [OK] Aucun secret." "Green"
    }
} else {
    $leaksStatut = "SKIP"
    $leaksLines += "[SKIP] gitleaks non disponible."
    Write-Status "  [SKIP] gitleaks absent." "Yellow"
}

$Sections += [PSCustomObject]@{
    titre  = "[3/3] GITLEAKS - Secrets"
    statut = $leaksStatut
    lignes = $leaksLines
}

Pop-Location

# ===========================================================================
# RESULTAT GLOBAL
# ===========================================================================
$resultat = "OK"
if ($HasSecrets) { $resultat = "CRITIQUE" }
elseif ($HasErrors) { $resultat = "AVERTISSEMENT" }

Write-Status ""
Write-Status "  ============================================================"
switch ($resultat) {
    "CRITIQUE"      { Write-Status "  RESULTAT : CRITIQUE - Secrets detectes !" "Red" }
    "AVERTISSEMENT" { Write-Status "  RESULTAT : AVERTISSEMENT - Problemes detectes" "Yellow" }
    default         { Write-Status "  RESULTAT : OK - Aucun probleme detecte" "Green" }
}
Write-Status "  ============================================================"
Write-Status ""

# ===========================================================================
# RAPPORT TXT (toujours genere)
# ===========================================================================
# Supprimer tous les anciens rapports, garder uniquement le dernier
Get-ChildItem -Path $AuditDir -Filter "rapport_securite_*" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }

$txtLines = @()
$txtLines += "================================================================"
$txtLines += "  VELOCIRAPTOR-IA - Rapport Audit Securite IHM"
$txtLines += "  Date      : $Date"
$txtLines += "  Cible     : scripts\ia_forensic\"
$txtLines += "  Resultat  : $resultat"
$txtLines += "================================================================"
$txtLines += ""
foreach ($sec in $Sections) {
    $txtLines += "----------------------------------------------------------------"
    $txtLines += "  $($sec.titre)  [Statut: $($sec.statut)]"
    $txtLines += "----------------------------------------------------------------"
    foreach ($lg in $sec.lignes) { $txtLines += $lg }
    $txtLines += ""
}
$txtLines += "================================================================"
$txtLines += "  FIN DU RAPPORT"
$txtLines += "================================================================"

[System.IO.File]::WriteAllLines($TxtFile, $txtLines,
    (New-Object System.Text.UTF8Encoding $false))
Write-Status "  [OK] Rapport TXT : $(Split-Path $TxtFile -Leaf)" "Green"


# ===========================================================================
# RAPPORT PDF professionnel via generateur Go embarque
# ===========================================================================
Write-Status "  Generation du rapport PDF professionnel..."

$tmpDir = Join-Path $AuditDir ".tmp_pdfgen"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$goSrc  = Join-Path $tmpDir "genpdf.go"
$goExe  = Join-Path $tmpDir "genpdf.exe"
$goMod  = Join-Path $tmpDir "go.mod"

[System.IO.File]::WriteAllText($goMod, "module genpdf`ngo 1.21`n",
    (New-Object System.Text.UTF8Encoding $false))

# Code Go - generateur PDF professionnel avec mise en page soignee
$goLines = @(
    'package main',
    'import ("bufio";"fmt";"os";"strings")',
    '',
    'const (pW=595.28;pH=841.89;mL=50.0;mR=50.0;mT=780.0;mB=50.0)',
    '',
    'type Doc struct {',
    '    objs []string; pageIDs []int',
    '    catID,treeID,fnID,fbID,fiID int',
    '}',
    '',
    'func (d *Doc) add(body string) int {',
    '    d.objs = append(d.objs, body)',
    '    return len(d.objs)',
    '}',
    '',
    'func esc(s string) string {',
    '    s=strings.ReplaceAll(s,"\\\\","\\\\\\\\");s=strings.ReplaceAll(s,"(","\\\\(");s=strings.ReplaceAll(s,")","\\\\)")',
    '    // Garder uniquement ASCII imprimable',
    '    var b strings.Builder',
    '    for _,r:=range s { if r>=32 && r<=126 { b.WriteRune(r) } else { b.WriteRune(32) } }',
    '    return b.String()',
    '}',
    '',
    'func (d *Doc) newPage(lines []string) {',
    '    resID := d.add(fmt.Sprintf("<<\\n/Font<</F1 %d 0 R/F2 %d 0 R/F3 %d 0 R>>\\n>>",d.fnID,d.fbID,d.fiID))',
    '    var sb strings.Builder',
    '    sb.WriteString("BT\\n")',
    '    y := mT',
    '    for _,ln := range lines {',
    '        // Determiner le style de la ligne',
    '        isSep  := strings.HasPrefix(ln,"===")||strings.HasPrefix(ln,"---")',
    '        isHdr1 := strings.HasPrefix(ln,"  VELOCIRAPTOR")',
    '        isHdr2 := strings.Contains(ln,"[1/")||strings.Contains(ln,"[2/")||strings.Contains(ln,"[3/")',
    '        isOK   := strings.Contains(ln,"[OK]")',
    '        isCrit := strings.Contains(ln,"CRITIQUE")||strings.Contains(ln,"ERREUR")',
    '        isWarn := strings.Contains(ln,"AVERTISSEMENT")||strings.Contains(ln,"[!]")',
    '        isURL  := strings.Contains(ln,"https://")',
    '',
    '        // Couleur',
    '        switch {',
    '        case isCrit: sb.WriteString("0.8 0.1 0.1 rg\\n")',
    '        case isWarn: sb.WriteString("0.75 0.4 0 rg\\n")',
    '        case isOK:   sb.WriteString("0 0.5 0.2 rg\\n")',
    '        case isSep||isHdr1: sb.WriteString("0.08 0.18 0.45 rg\\n")',
    '        case isHdr2: sb.WriteString("0.15 0.35 0.6 rg\\n")',
    '        case isURL:  sb.WriteString("0 0.4 0.8 rg\\n")',
    '        default:     sb.WriteString("0.15 0.2 0.3 rg\\n")',
    '        }',
    '',
    '        // Police et taille',
    '        fs := 8.0',
    '        fn := "F1"',
    '        if isHdr1 { fn="F2"; fs=10.0 }',
    '        if isHdr2 { fn="F2"; fs=8.5 }',
    '        if isSep  { fn="F1"; fs=7.5 }',
    '        if isCrit||isWarn { fn="F2"; fs=8.0 }',
    '',
    '        // Fond colore pour les lignes importantes',
    '        if isCrit {',
    '            sb.WriteString(fmt.Sprintf("0.98 0.93 0.93 rg\\n%.2f %.2f %.2f %.2f re f\\n",mL-2,y-2,pW-mL-mR+4,fs+4))',
    '            sb.WriteString("0.8 0.1 0.1 rg\\n")',
    '        } else if isOK {',
    '            sb.WriteString(fmt.Sprintf("0.93 0.98 0.93 rg\\n%.2f %.2f %.2f %.2f re f\\n",mL-2,y-2,pW-mL-mR+4,fs+4))',
    '            sb.WriteString("0 0.5 0.2 rg\\n")',
    '        }',
    '',
    '        sb.WriteString(fmt.Sprintf("/%s %.1f Tf 1 0 0 1 %.2f %.2f Tm (%s) Tj\\n",fn,fs,mL,y,esc(ln)))',
    '        y -= fs*1.5',
    '        if isSep { y -= 2 } // espace apres separateur',
    '    }',
    '    sb.WriteString("ET\\n")',
    '',
    '    cs := sb.String()',
    '    cID := d.add(fmt.Sprintf("<< /Length %d >>\\nstream\\n%s\\nendstream",len(cs),cs))',
    '    pid := d.add(fmt.Sprintf("<<\\n/Type /Page\\n/Parent %d 0 R\\n/MediaBox [0 0 %.2f %.2f]\\n/Contents %d 0 R\\n/Resources %d 0 R\\n>>",d.treeID,pW,pH,cID,resID))',
    '    d.pageIDs = append(d.pageIDs,pid)',
    '    _=resID',
    '}',
    '',
    'func main() {',
    '    if len(os.Args)<3{fmt.Fprintln(os.Stderr,"usage: genpdf <txt> <pdf>");os.Exit(1)}',
    '    f,err:=os.Open(os.Args[1])',
    '    if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}',
    '    defer f.Close()',
    '    var all []string',
    '    sc:=bufio.NewScanner(f)',
    '    for sc.Scan(){all=append(all,sc.Text())}',
    '',
    '    d := &Doc{}',
    '    d.catID  = d.add("")',
    '    d.treeID = d.add("")',
    '    d.fnID   = d.add("<<\\n/Type /Font\\n/Subtype /Type1\\n/BaseFont /Helvetica\\n/Encoding /WinAnsiEncoding\\n>>")',
    '    d.fbID   = d.add("<<\\n/Type /Font\\n/Subtype /Type1\\n/BaseFont /Helvetica-Bold\\n/Encoding /WinAnsiEncoding\\n>>")',
    '    d.fiID   = d.add("<<\\n/Type /Font\\n/Subtype /Type1\\n/BaseFont /Helvetica-Oblique\\n/Encoding /WinAnsiEncoding\\n>>")',
    '',
    '    // Calcul lignes par page',
    '    linesPerPage := int((mT-mB)/12.0)',
    '    for len(all)>0{',
    '        n:=linesPerPage; if n>len(all){n=len(all)}',
    '        d.newPage(all[:n]); all=all[n:]',
    '    }',
    '    if len(d.pageIDs)==0{d.newPage([]string{"(rapport vide)"})}',
    '',
    '    // Arbre de pages',
    '    var kids strings.Builder',
    '    for i,pid:=range d.pageIDs{if i>0{kids.WriteString(" ")};kids.WriteString(fmt.Sprintf("%d 0 R",pid))}',
    '    d.objs[d.catID-1]=fmt.Sprintf("<<\\n/Type /Catalog\\n/Pages %d 0 R\\n>>",d.treeID)',
    '    d.objs[d.treeID-1]=fmt.Sprintf("<<\\n/Type /Pages\\n/Kids [%s]\\n/Count %d\\n>>",kids.String(),len(d.pageIDs))',
    '',
    '    // Ecriture PDF',
    '    out,_:=os.Create(os.Args[2])',
    '    defer out.Close()',
    '    offs:=make(map[int]int)',
    '    pos:=0',
    '    wr:=func(s string){n,_:=fmt.Fprint(out,s);pos+=n}',
    '    wr("%PDF-1.4\\n")',
    '    for i,body:=range d.objs{',
    '        offs[i+1]=pos',
    '        wr(fmt.Sprintf("%d 0 obj\\n%s\\nendobj\\n",i+1,body))',
    '    }',
    '    xref:=pos',
    '    wr(fmt.Sprintf("xref\\n0 %d\\n0000000000 65535 f \\n",len(d.objs)+1))',
    '    for i:=1;i<=len(d.objs);i++{wr(fmt.Sprintf("%010d 00000 n \\n",offs[i]))}',
    '    wr(fmt.Sprintf("trailer\\n<< /Size %d /Root %d 0 R >>\\nstartxref\\n%d\\n%%%%EOF\\n",len(d.objs)+1,d.catID,xref))',
    '    fmt.Println("OK")',
    '}'
)

[System.IO.File]::WriteAllLines($goSrc, $goLines,
    (New-Object System.Text.UTF8Encoding $false))

Push-Location $tmpDir
$buildErr = go build -o $goExe . 2>&1
$buildOK  = ($LASTEXITCODE -eq 0) -and (Test-Path $goExe)
Pop-Location

if ($buildOK) {
    $runOut = & $goExe $TxtFile $PdfFile 2>&1
} else {
    Push-Location $tmpDir
    $runOut = go run $goSrc $TxtFile $PdfFile 2>&1
    Pop-Location
}

if ((Test-Path $PdfFile) -and (Get-Item $PdfFile -ErrorAction SilentlyContinue).Length -gt 500) {
    Write-Status "  [OK] Rapport PDF : $(Split-Path $PdfFile -Leaf)" "Green"
    # Supprimer le TXT maintenant que le PDF est genere
    Remove-Item $TxtFile -Force -ErrorAction SilentlyContinue
    Write-Status "  [i] Rapport TXT supprime (PDF genere avec succes)" "Cyan"
} else {
    Write-Status "  [!] PDF non genere (TXT conserve) : $buildErr $runOut" "Yellow"
}

# Nettoyage
Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Status ""
if ($HasSecrets) {
    Write-Status "  [!] ATTENTION : Secrets detectes ! Ne pas distribuer." "Red"
}
Write-Status "  Rapport disponible dans : $AuditDir" "Cyan"
Write-Status ""

if ($HasSecrets) { exit 1 }
exit 0
