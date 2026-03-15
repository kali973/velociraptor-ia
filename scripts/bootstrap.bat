@echo off
:: =============================================================================
:: bootstrap.bat - Lanceur unique Velociraptor-IA
:: UTILISATION : Clic droit > "Executer en tant qu'Administrateur"
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

echo  Lancement de la compilation...
echo.

powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%compilateur.ps1"
set "PS_CODE=%errorlevel%"

:: FIX B8: verifier le code de retour de compilateur.ps1.
:: Code 1 = erreur critique (secrets detectes ou compilation echouee).
:: Code 0 = succes. Autre = avertissements non bloquants (CVE Go stdlib).
if "%PS_CODE%"=="1" (
    echo.
    echo  ERREUR : compilation echouee ou secrets detectes. Consultez les logs.
    pause
    exit /b 1
)
