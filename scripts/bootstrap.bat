@echo off
setlocal enabledelayedexpansion
title velociraptor - Bootstrap

REM =============================================================================
REM  bootstrap.bat - Lanceur unique velociraptor (Forge IA de collecteurs forensic)
REM
REM  v0.3.0 :
REM    - Le binaire velociraptor.exe est compile en GUI subsystem (-H=windowsgui)
REM    - Aucune fenetre console pour le serveur (l'utilisateur l'arrete via l'IHM)
REM    - Le binaire ouvre lui-meme le browser au demarrage
REM
REM  Sequence : kill, log, fix-imports, deps, build (gui subsystem),
REM             setup vault si premier lancement, lancement detache, exit.
REM
REM  Conventions identiques a rf-sandbox-go :
REM    - Aucun accent dans les echo (compat cp850/cp1252)
REM    - GOFLAGS=-buildvcs=false (evite les erreurs Git VCS sur poste sans .git)
REM    - Tous les binaires Go compiles dans build\
REM    - Pour arreter le serveur : bouton ARRET dans l'IHM
REM
REM  UTILISATION :
REM    Double-clic, ou bien :
REM    cd scripts && bootstrap.bat
REM =============================================================================

echo.
echo  [BOOTSTRAP] Demarrage du script bootstrap.bat...
echo  [BOOTSTRAP] Repertoire courant : %CD%
echo  [BOOTSTRAP] Chemin du script   : %~dp0

REM --- Remonter a la racine du projet ------------------------------------------
cd /d "%~dp0\.." 2>nul
if errorlevel 1 (
    echo  [ERREUR] Impossible d'acceder au repertoire parent du script
    echo  [ERREUR] Chemin tente : %~dp0\..
    pause
    exit /b 1
)
echo  [BOOTSTRAP] Repertoire projet  : %CD%
echo.

set "GOFLAGS=-buildvcs=false"
echo  [BOOTSTRAP] GOFLAGS=-buildvcs=false positionne

REM --- 0. Si le serveur tourne deja, on ouvre juste le navigateur --------------
where curl.exe >nul 2>&1
if not errorlevel 1 (
    curl.exe -s -o nul -w "%%{http_code}" http://localhost:8767/api/health 2>nul | findstr "200" >nul
    if not errorlevel 1 (
        echo  [INFO] Serveur deja actif sur http://localhost:8767
        echo         Ouverture du navigateur...
        start "" http://localhost:8767
        timeout /t 2 /nobreak >nul
        exit /b 0
    )
)

REM --- 1. Kill des sessions precedentes ----------------------------------------
echo  [BOOTSTRAP] Kill des sessions precedentes...
for %%P in (velociraptor.exe llama-server.exe) do (
    start /B "" taskkill /F /IM %%P >nul 2>&1
)
ping -n 3 127.0.0.1 >nul 2>&1
echo  [BOOTSTRAP] Kill termine

REM --- 2. Rotation du log ------------------------------------------------------
if not exist "logs" mkdir "logs" >nul 2>&1
if exist "logs\velociraptor.log" (
    if exist "logs\velociraptor.log.prev" del /q "logs\velociraptor.log.prev" >nul 2>&1
    move /y "logs\velociraptor.log" "logs\velociraptor.log.prev" >nul 2>&1
)
echo  [BOOTSTRAP] Log rote
echo.

REM --- 3. Verification de Go ---------------------------------------------------
where go >nul 2>&1
if errorlevel 1 (
    echo  [ERREUR] Go non detecte dans le PATH.
    echo          Installer depuis https://go.dev/dl/ - Go 1.21+ requis.
    pause
    exit /b 1
)
for /f "tokens=3" %%V in ('go version') do echo  [BOOTSTRAP] %%V detecte

REM --- 4. Fix automatique des imports si projet forke depuis rf-sandbox-go ----
if exist tools\fix-imports\main.go (
    echo  [BOOTSTRAP] Verification des imports Go...
    go run tools\fix-imports\main.go
    if errorlevel 1 (
        echo.
        echo  [ERREUR] fix-imports a echoue. Compilation interrompue.
        pause
        exit /b 1
    )
)

REM --- 5. Compilation du binaire principal -------------------------------------
if not exist build mkdir build >nul 2>&1

echo  [BOOTSTRAP] Synchronisation go.mod / go.sum...
go mod tidy
if errorlevel 1 (
    echo.
    echo  [ERREUR] go mod tidy a echoue.
    pause
    exit /b 1
)

if exist tools\check-deps\main.go (
    echo  [BOOTSTRAP] Diagnostic des dependances locales...
    go run tools\check-deps\main.go
    if errorlevel 1 (
        echo.
        echo  [ERREUR] Des packages locaux du module sont introuvables.
        pause
        exit /b 1
    )
)

REM 5c. Compilation EN MODE GUI SUBSYSTEM
REM    -H=windowsgui supprime la console qui s'ouvrirait normalement au lancement
REM    -s -w stripe les symboles pour reduire la taille
echo  [BOOTSTRAP] Compilation de build\velociraptor.exe en mode GUI subsystem...
go build -ldflags="-s -w -H=windowsgui" -o build\velociraptor.exe .\cmd
if errorlevel 1 (
    echo.
    echo  [ERREUR] Compilation de velociraptor.exe echouee.
    pause
    exit /b 1
)
for %%A in (build\velociraptor.exe) do echo  [OK] build\velociraptor.exe          %%~zA octets

REM --- 6. Copie de la config par defaut ----------------------------------------
if not exist build\config mkdir build\config >nul 2>&1
if not exist build\config\config.json (
    copy /y config\config.json build\config\config.json >nul
    echo  [BOOTSTRAP] config.json copie dans build\config\
) else (
    echo  [BOOTSTRAP] config.json deja present dans build\config\
)
REM Copie aussi du dossier bin pour que velociraptor.exe (Velocidex) soit visible
if exist bin (
    if not exist build\bin mkdir build\bin >nul 2>&1
    xcopy /y /e /q bin\* build\bin\ >nul 2>&1
)

REM --- 7. Setup initial du vault si premier lancement --------------------------
REM Note : -setup utilise un mode console interactif. Compile en GUI, le binaire
REM n'aurait pas de console. On force ici une compilation classique pour le setup
REM uniquement.
if not exist build\config\.vault.key (
    echo.
    echo  [BOOTSTRAP] Premier lancement detecte - configuration interactive
    echo  [BOOTSTRAP] Compilation d'un binaire console temporaire pour le setup...
    go build -o build\velociraptor-setup.exe .\cmd
    if errorlevel 1 (
        echo  [ERREUR] Compilation du binaire setup echouee.
        pause
        exit /b 1
    )
    echo.
    pushd build
    velociraptor-setup.exe -setup
    set "SETUP_RC=!errorlevel!"
    del /q velociraptor-setup.exe >nul 2>&1
    popd
    if !SETUP_RC! neq 0 (
        echo.
        echo  [ERREUR] Setup interrompu - code retour !SETUP_RC!
        pause
        exit /b !SETUP_RC!
    )
) else (
    echo  [BOOTSTRAP] Vault deja initialise - .vault.key present
)

REM --- 7b. Compilation et execution de setup-moteur.exe ---------------------
REM Le moteur IA local (llama.cpp + GGUF) est independant du binaire principal.
REM Compilation : un binaire CLI separe build\setup-moteur.exe.
REM Execution : si moteur\llama-server.exe absent OU aucun .gguf dans moteur\models\,
REM on lance setup-moteur.exe pour telecharger le modele par defaut.
echo.
echo  [BOOTSTRAP] Compilation de build\setup-moteur.exe...
go build -o build\setup-moteur.exe .\cmd\setup-moteur
if errorlevel 1 (
    echo  [ERREUR] Compilation de setup-moteur.exe echouee.
    pause
    exit /b 1
)
for %%A in (build\setup-moteur.exe) do echo  [OK] build\setup-moteur.exe         %%~zA octets

REM --- 7c. Verification / installation du moteur IA local ---------------------
REM setup-moteur.exe est idempotent ET auto-reparateur :
REM   - detecte les incoherences (ex: llama-server CPU sur machine GPU)
REM   - nettoie les modeles partiels et archives orphelines
REM   - ne re-telecharge pas ce qui est deja present
REM
REM On l'appelle inconditionnellement a chaque bootstrap. Si tout est en
REM ordre l'overhead est < 1s. Sinon il telecharge ce qui manque.
echo.
echo  [BOOTSTRAP] Verification / installation du moteur IA local...
pushd build
setup-moteur.exe
set "SETUP_MOTEUR_RC=!errorlevel!"
popd
if !SETUP_MOTEUR_RC! neq 0 (
    echo.
    echo  [WARN] setup-moteur.exe a renvoye le code !SETUP_MOTEUR_RC!
    echo         Le serveur va demarrer quand meme - le mode heuristique sera utilise.
    echo         Vous pouvez relancer build\setup-moteur.exe plus tard.
    echo.
)

REM --- 8. Demarrage du serveur en arriere-plan ---------------------------------
echo.
echo  [BOOTSTRAP] Demarrage du serveur en arriere-plan...
pushd build
REM start /B sans titre : pas de fenetre console car binaire compile en GUI subsystem
start "" /B velociraptor.exe -ui
popd

REM --- 9. Attente que le serveur soit pret -------------------------------------
echo  [BOOTSTRAP] Attente de la disponibilite du serveur...
set /a TRIES=0
:WAIT_SERVER
set /a TRIES+=1
if !TRIES! gtr 30 (
    echo  [ERREUR] Le serveur ne repond pas apres 15s.
    echo          Voir logs\velociraptor.log pour le diagnostic.
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
where curl.exe >nul 2>&1
if errorlevel 1 (
    if !TRIES! geq 5 goto SERVER_READY
    goto WAIT_SERVER
)
curl.exe -s -o nul -w "%%{http_code}" http://localhost:8767/api/health 2>nul | findstr "200" >nul
if errorlevel 1 goto WAIT_SERVER

:SERVER_READY
echo  [OK] Serveur pret apres !TRIES!s
echo.
echo  [BOOTSTRAP] Le binaire velociraptor.exe ouvre le browser automatiquement.
echo               Pour arreter le serveur, utilise le bouton ARRET dans l'IHM.
echo.
timeout /t 2 /nobreak >nul
endlocal
exit /b 0
