@echo off
rem Double-click launcher. It finds Python 3.11 or newer and saves results in a new
rem readiness-run folder in your home folder. No PowerShell policy change is needed.
setlocal
rem Never run a py or python placed in the current folder, and report the real exit code.
set "NoDefaultCurrentDirectoryInExePath=1"
set "ERRORLEVEL="
set "palma_check=import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
set "palma_exe="
set "palma_custom="
if defined PALMA_PYTHON set "palma_custom=%PALMA_PYTHON:"=%"
if not defined palma_custom goto find_python
"%palma_custom%" -I -S -c "%palma_check%" >nul 2>&1
if errorlevel 1 goto invalid_python
set palma_exe="%palma_custom%"
goto run_scan

:invalid_python
echo PALMA_PYTHON must name Python 3.11 or newer.
pause
exit /b 2

:find_python
py -3 -I -S -c "%palma_check%" >nul 2>&1
if errorlevel 1 goto try_python
set "palma_exe=py -3"
goto run_scan

:try_python
python -I -S -c "%palma_check%" >nul 2>&1
if errorlevel 1 goto missing_python
set "palma_exe=python"
goto run_scan

:missing_python
echo Palma needs Python 3.11 or newer. No Python packages are required.
echo If it is already installed, set PALMA_PYTHON to its executable path.
pause
exit /b 2

:run_scan
%palma_exe% -I -S "%~dp0palma-scan.py" run --open %*
set "palma_result=%ERRORLEVEL%"
if "%palma_result%"=="0" echo Finished. Your report is saved locally.
pause
exit /b %palma_result%
