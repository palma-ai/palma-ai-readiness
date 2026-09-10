@echo off
rem Double-click launcher. Results go beside the skill folder.
cd /d "%~dp0..\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
set "palma_result=%ERRORLEVEL%"
if "%palma_result%"=="0" echo Finished. Your report is saved locally.
pause
exit /b %palma_result%
