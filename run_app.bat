@echo off
echo Starting Secure Sight Web Application...
cd /d "%~dp0"
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)
python -m app.app
pause
