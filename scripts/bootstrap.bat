@echo off
:: =============================================================================
:: bootstrap.bat - Lanceur unique Velociraptor-IA
::
:: Comportement automatique :
::   - Verifie les prerequis (Go, GCC, Node.js, Make)
::   - Compile l'IHM forensique IA (scripts\ia_forensic\)
::   - Compile Velociraptor (make windows) si demande
::   - Lance l'IHM sur http://localhost:8767
::
:: UTILISATION :
::   Clic droit sur bootstrap.bat > "Executer en tant qu'Administrateur"
:: =============================================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ERREUR : Ce script doit etre execute en tant qu'Administrateur.
    echo  -> Clic droit sur bootstrap.bat puis "Executer en tant qu'administrateur"
    echo.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo    Velociraptor-IA - Bootstrap
echo  ==========================================
echo.

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."

:: Lancer le compilateur PowerShell qui orchestre tout
echo  Lancement de la compilation...
echo.

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%compilateur.ps1"

if %errorlevel% neq 0 (
    echo.
    echo  ERREUR : compilation echouee (code %errorlevel%)
    pause
    exit /b %errorlevel%
)

echo.
echo  Bootstrap termine avec succes.
echo.
pause
