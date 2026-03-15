@echo off
:: ================================================================
:: lancer.bat - Velociraptor-IA (lancement IHM + Velociraptor)
::
::  1. Detecte le proxy systeme Windows (registre + env)
::  2. Met a jour la config proxy de l'IHM
::  3. Lance l'IHM forensique IA (ia_forensic.exe)
::     -> http://localhost:8767
::  4. L'IHM permet ensuite de lancer velociraptor.exe gui
:: ================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ==========================================
echo    Velociraptor-IA - Demarrage
echo  ==========================================
echo.

:: Verification IHM
if not exist "%~dp0ia_forensic.exe" (
    echo  ERREUR : ia_forensic.exe introuvable.
    echo  Relancez bootstrap.bat pour compiler.
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

powershell -ExecutionPolicy Bypass -File "%~dp0scripts\update_proxy.ps1" -ProxyActive %PROXY_ACTIVE%

if "%PROXY_ACTIVE%"=="1" (
    echo  [OK] Proxy detecte - proxy_url de config\config.json conserve.
) else (
    echo  [OK] Aucun proxy - connexion directe.
)

:: Lancement IHM
echo.
echo  Lancement IHM sur http://localhost:8767 ...
echo.
start "" http://localhost:8767
ia_forensic.exe -port 8767

endlocal
pause
