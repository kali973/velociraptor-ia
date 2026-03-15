@echo off
:: ================================================================
:: lancer.bat - Velociraptor-IA (lancement IHM)
:: Ce fichier est dans scripts\ — il lance ia_forensic.exe
:: qui se trouve dans le meme repertoire.
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

:: update_proxy.ps1 est dans le meme dossier que lancer.bat (scripts\)
powershell -ExecutionPolicy Bypass -File "%~dp0update_proxy.ps1" -ProxyActive %PROXY_ACTIVE%

if "%PROXY_ACTIVE%"=="1" (
    echo  [OK] Proxy detecte - proxy_url conserve.
) else (
    echo  [OK] Aucun proxy - connexion directe.
)

:: Lancement IHM
:: Note : ia_forensic.exe ouvre lui-meme le navigateur (openBrowser interne).
:: Ne pas faire "start http://..." ici pour eviter le double onglet.
echo.
echo  Lancement IHM sur http://localhost:8767 ...
echo.
ia_forensic.exe -port 8767

endlocal
pause
