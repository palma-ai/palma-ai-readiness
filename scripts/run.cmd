@echo off
rem Double-click launcher. It finds Python 3.11 or newer and saves results in a new
rem readiness-run folder in your home folder. No PowerShell policy change is needed.
setlocal
set "palma_check=import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
set "palma_exe="
if defined PALMA_PYTHON set palma_exe="%PALMA_PYTHON%"
if not defined palma_exe py -3 -I -S -c "%palma_check%" >nul 2>&1 && set "palma_exe=py -3"
if not defined palma_exe python -I -S -c "%palma_check%" >nul 2>&1 && set "palma_exe=python"
if not defined palma_exe echo Palma needs Python 3.11 or newer. No Python packages are required.& echo If it is already installed, set PALMA_PYTHON to its executable path.& pause & exit /b 2
%palma_exe% -I -S "%~dp0palma-scan.py" run --open %*
set "palma_result=%ERRORLEVEL%"
if "%palma_result%"=="0" echo Finished. Your report is saved locally.
pause
exit /b %palma_result%
