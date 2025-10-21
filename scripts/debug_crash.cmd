@echo off
REM Debug crash with CDB - Break on exception and analyze

setlocal

set BUILD_CONFIG=x64-Clang-Debug
if "%MW05_BUILD_CONFIG%" neq "" set BUILD_CONFIG=%MW05_BUILD_CONFIG%

set EXE=out\build\%BUILD_CONFIG%\Mw05Recomp\Mw05Recomp.exe

if not exist "%EXE%" (
    echo Error: Executable not found at %EXE%
    exit /b 1
)

echo Launching with CDB to debug crash...
echo.
echo CDB will break on first-chance exceptions
echo When it breaks, you can:
echo   k   - Show call stack
echo   r   - Show registers
echo   u   - Disassemble at current location
echo   g   - Continue execution
echo   q   - Quit
echo.

REM Break on first-chance exceptions
REM -g = go on initial breakpoint
REM -G = go on final breakpoint
REM -o = debug child processes
REM sxe = break on first-chance exception
cdb -g -c "sxe av; sxe dz; g" "%EXE%"

