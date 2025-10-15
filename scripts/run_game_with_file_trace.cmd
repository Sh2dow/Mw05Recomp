@echo off
REM Run MW05 with file I/O tracing enabled
REM This batch file ensures environment variables are properly inherited

set MW05_FILE_LOG=1
set MW05_HOST_TRACE_HOSTOPS=1
set MW05_HOST_TRACE_IMPORTS=0
set MW05_TRACE_KERNEL=1
set MW05_PM4_TRACE=0
set MW05_STREAM_BRIDGE=1
set MW05_STREAM_ANY_LR=1
set MW05_STREAM_FALLBACK_BOOT=1
set MW05_FORCE_PRESENT=0

echo ========================================
echo MW05 File I/O Trace Test
echo ========================================
echo Environment variables:
echo   MW05_FILE_LOG=%MW05_FILE_LOG%
echo   MW05_HOST_TRACE_HOSTOPS=%MW05_HOST_TRACE_HOSTOPS%
echo.
echo Starting game...
echo.

cd /d "%~dp0..\out\build\x64-Clang-Debug\Mw05Recomp"

REM Run game and redirect stderr
Mw05Recomp.exe 2> "%~dp0..\Traces\file_trace_stderr.txt"

echo.
echo Game exited.
echo.

REM Copy trace log if it exists
if exist "mw05_host_trace.log" (
    copy /Y "mw05_host_trace.log" "%~dp0..\Traces\file_trace.log" > nul
    echo Trace log copied to Traces\file_trace.log
    echo.
    
    REM Count lines
    for /f %%A in ('find /c /v "" ^< "mw05_host_trace.log"') do set LINE_COUNT=%%A
    echo Trace log has %LINE_COUNT% lines
    
    REM Show first 30 lines
    echo.
    echo First 30 lines of trace:
    echo ----------------------------------------
    powershell -Command "Get-Content 'mw05_host_trace.log' | Select-Object -First 30"
    echo ----------------------------------------
) else (
    echo ERROR: No trace log found!
    echo This means the trace system is not working.
)

echo.
pause

