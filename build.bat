@echo off
setlocal
cd /d "%~dp0"

echo [1/2] Initializing MSVC x64 build environment...
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to initialize MSVC x64 environment.
    exit /b 1
)

echo [2/2] Compiling launch_svc.cpp (Static Runtime /MT for standalone deployment)...
cl.exe /nologo /O2 /W4 /EHsc /MT /std:c++17 /DUNICODE /D_UNICODE launch_svc.cpp ^
    /link /OUT:launch_svc.exe ^
    wtsapi32.lib userenv.lib advapi32.lib

if %ERRORLEVEL% equ 0 (
    echo.
    echo ============================================================
    echo Build SUCCESSFUL: %~dp0launch_svc.exe
    echo ============================================================
) else (
    echo.
    echo [ERROR] Compilation failed.
    exit /b %ERRORLEVEL%
)

