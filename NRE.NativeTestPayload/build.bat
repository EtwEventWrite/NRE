@echo off
REM Build native test payload (MessageBox). Requires Visual Studio cl.exe or run from "x64 Native Tools Command Prompt".
setlocal
set OUT=bin\Release
if not exist "%OUT%" mkdir "%OUT%"
set EXE=%OUT%\NRE.NativeTestPayload.exe

where cl.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo cl.exe not in PATH. Run from "x64 Native Tools Command Prompt for VS" or:
    echo   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

cl.exe /nologo /O2 /W3 main.c /Fe:%EXE% user32.lib
if %ERRORLEVEL% neq 0 exit /b 1
echo Built: %EXE%
exit /b 0
