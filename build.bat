@echo off
cd /d "%~dp0"
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;C:\MinGW\bin;%PATH%"

where g++ >nul 2>&1
if %errorlevel% neq 0 (
    echo g++ not found. Install MinGW via MSYS2.
    pause & exit /b 1
)

echo Building...
g++ -O2 -std=c++17 -static -o proxy.exe proxy.cpp -lws2_32 -lwinhttp -lbcrypt
if %errorlevel% == 0 (
    echo Build OK: proxy.exe
) else (
    echo Build FAILED
)
pause
