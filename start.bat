@echo off
cd /d "%~dp0"
if not exist proxy.exe (
    echo proxy.exe not found, building first...
    call build.bat
)
if not exist auth.json (
    echo auth.json not found, logging in first...
    call auth.bat
)
proxy.exe
pause
