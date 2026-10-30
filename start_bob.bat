@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    call install.bat
    if errorlevel 1 exit /b 1
)
".venv\Scripts\python.exe" main.py --name Bob
if errorlevel 1 pause
