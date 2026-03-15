@echo off
:: ================================================================
:: lancer.bat - RF Sandbox Go (execution depuis cle USB)
::
::  1. Detecte le proxy systeme Windows (registre + env)
::     - Proxy actif  -> proxy de config\config.json conserve
::     - Pas de proxy -> proxy vide (connexion directe API RF)
::  2. Verifie le vault (cle + secrets)
::  3. Lance rf-sandbox.exe -ui
:: ================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ==========================================
echo    RF Sandbox Go - USB
echo  ==========================================
echo.

:: Verification des executables
if not exist "%~dp0rf-sandbox.exe" (
    echo  ERREUR : rf-sandbox.exe introuvable.
    echo  Relancez bootstrap.bat pour recompiler.
    pause
    exit /b 1
)
if not exist "%~dp0vault.exe" (
    echo  ERREUR : vault.exe introuvable.
    echo  Relancez bootstrap.bat pour recompiler.
    pause
    exit /b 1
)
if not exist "%~dp0update-proxy.exe" (
    echo  ERREUR : update-proxy.exe introuvable.
    echo  Relancez bootstrap.bat pour recompiler.
    pause
    exit /b 1
)

:: Detection du proxy systeme
echo  Detection du proxy reseau...
set "PROXY_ACTIVE=0"

for /f "tokens=3" %%v in (
    'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable 2^>nul'
) do ( if "%%v"=="0x1" set "PROXY_ACTIVE=1" )

if not "%HTTP_PROXY%"==""  set "PROXY_ACTIVE=1"
if not "%HTTPS_PROXY%"=="" set "PROXY_ACTIVE=1"

:: Mise a jour config\config.json via update-proxy.exe (Go natif)
"%~dp0update-proxy.exe" -proxy-active %PROXY_ACTIVE% -config "%~dp0config\config.json"

if "%PROXY_ACTIVE%"=="1" (
    echo  [OK] Proxy detecte - proxy de config\config.json utilise.
) else (
    echo  [OK] Aucun proxy - connexion directe a https://sandbox.recordedfuture.com
)

:: Verification du vault
echo.
echo  Verification du vault...
if not exist "%~dp0config\.vault.key" (
    echo  Premiere utilisation : initialisation du vault...
    vault.exe init
    if %errorlevel% neq 0 (
        echo  ERREUR : vault init echoue.
        pause
        exit /b 1
    )
    vault.exe seal
    if %errorlevel% neq 0 (
        echo  ERREUR : vault seal echoue.
        pause
        exit /b 1
    )
) else (
    vault.exe status
)

:: Lancement
echo.
echo  Lancement sur http://localhost:8766 ...
echo.
start "" http://localhost:8766
rf-sandbox.exe -ui

endlocal
pause
