@echo off
:: =============================================================================
:: bootstrap.bat - Lanceur unique RF Sandbox Go
::
:: Comportement automatique :
::   - Cle USB detectee  -> compile + installe tout sur la cle
::   - Pas de cle USB    -> compile normalement dans le dossier courant
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
echo    RF Sandbox Go - Bootstrap
echo  ==========================================
echo.

set "SCRIPT_DIR=%~dp0"
set "PROJECT_DIR=%SCRIPT_DIR%.."
set "COMPILER=%PROJECT_DIR%\compilateur.exe"

:: Si compilateur.exe absent, on le genere d'abord avec go build
if not exist "%COMPILER%" (
    echo  [0] compilateur.exe absent - compilation initiale...
    pushd "%PROJECT_DIR%"
    go build -ldflags="-s -w" -o compilateur.exe ./cmd/compilateur
    if %errorlevel% neq 0 (
        echo  ERREUR : go build compilateur echoue. Verifiez que Go est installe.
        popd
        pause
        exit /b 1
    )
    popd
    echo  [OK] compilateur.exe compile.
    echo.
)

:: Lance compilateur.exe qui orchestre tout :
::   1. Detection USB automatique
::   2. Audit securite (audit-securite.exe)
::   3. Compilation de tous les binaires Go
::   4. Vault init + seal
::   5. Lancement UI (local) ou installation USB
echo  Lancement du compilateur...
echo.
"%COMPILER%"

if %errorlevel% neq 0 (
    echo.
    echo  ERREUR : compilateur.exe code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo  Bootstrap termine avec succes.
echo.
pause
