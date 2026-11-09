@echo off
REM ============================================================================
REM build_exe.bat - build a self-contained backuper.exe (PyInstaller onefile).
REM
REM Prerequisites (one-time):
REM     python -m pip install pyinstaller
REM (the script installs it automatically when missing)
REM
REM Output: dist\backuper.exe  (build artifacts go to build\)
REM ============================================================================

setlocal
cd /d "%~dp0"

python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo pyinstaller not found - installing...
    python -m pip install pyinstaller || exit /b 1
)

REM Onefile console build. Entry point is backuper\__main__.py; --paths .
REM makes the backuper package importable during analysis (the relative
REM "from backuper.cli import main" in __main__.py resolves through it).
python -m PyInstaller ^
    --onefile ^
    --console ^
    --name backuper ^
    --paths . ^
    backuper\__main__.py ^
    --distpath dist ^
    --workpath build ^
    --clean ^
    --noconfirm
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)

REM Post-build sanity check: the exe must answer --version with exit 0.
dist\backuper.exe --version
if errorlevel 1 (
    echo SANITY CHECK FAILED: dist\backuper.exe --version
    exit /b 1
)
echo BUILD OK: dist\backuper.exe
endlocal
