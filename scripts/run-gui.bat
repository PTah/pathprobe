@echo off
setlocal
cd /d "%~dp0\.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m pathprobe.gui %*
) else (
  python -m pathprobe.gui %*
)
endlocal
