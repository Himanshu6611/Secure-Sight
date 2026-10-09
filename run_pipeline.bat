@echo off
echo Running Secure Sight Data & Model Pipeline...
cd /d "%~dp0"
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)
python scripts/run_pipeline.py %*
pause
