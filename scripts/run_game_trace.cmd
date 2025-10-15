@echo off
REM Run MW05 with minimal tracing enabled
REM This batch file ensures environment variables are properly set

set MW05_HOST_TRACE_HOSTOPS=1
set MW05_HOST_TRACE_IMPORTS=0
set MW05_TRACE_KERNEL=0
set MW05_PM4_TRACE=0

echo Starting MW05 with minimal tracing...
echo Environment:
echo   MW05_HOST_TRACE_HOSTOPS=%MW05_HOST_TRACE_HOSTOPS%
echo   MW05_HOST_TRACE_IMPORTS=%MW05_HOST_TRACE_IMPORTS%
echo.

cd /d "%~dp0..\out\build\x64-Clang-Debug\Mw05Recomp"

Mw05Recomp.exe 2> "%~dp0minimal_stderr.txt"

echo.
echo Game exited. Check for trace log...
if exist "mw05_host_trace.log" (
    copy /Y "mw05_host_trace.log" "%~dp0minimal_trace.log" > nul
    echo Trace log copied to Traces\minimal_trace.log
) else (
    echo No trace log found
)

pause

