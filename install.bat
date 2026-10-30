@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt --index-url https://pypi.org/simple
if errorlevel 1 goto failed
exit /b 0
:failed
echo Setup failed. Install Python 3.12 with Tcl/Tk, then retry.
pause
exit /b 1
