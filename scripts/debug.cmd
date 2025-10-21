@echo off
REM MW05 Debug Launcher - Single script to replace all run_*.ps1 scripts
REM Usage: debug.cmd [cdb|windbg|vdswap|pm4|normal]

setlocal

REM Determine build configuration
set BUILD_CONFIG=x64-Clang-Debug
if "%MW05_BUILD_CONFIG%" neq "" set BUILD_CONFIG=%MW05_BUILD_CONFIG%

REM Set executable path
set EXE=out\build\%BUILD_CONFIG%\Mw05Recomp\Mw05Recomp.exe

REM Check if executable exists
if not exist "%EXE%" (
    echo Error: Executable not found at %EXE%
    echo Build the project first with: build_cmd.ps1 -Stage app
    exit /b 1
)

REM Parse command line argument
set MODE=%1
if "%MODE%"=="" set MODE=normal

REM Handle different debug modes
if /i "%MODE%"=="cdb" goto :launch_cdb
if /i "%MODE%"=="windbg" goto :launch_windbg
if /i "%MODE%"=="vdswap" goto :launch_vdswap
if /i "%MODE%"=="pm4" goto :launch_pm4
if /i "%MODE%"=="normal" goto :launch_normal
if /i "%MODE%"=="help" goto :show_help

echo Error: Unknown mode '%MODE%'
goto :show_help

:launch_cdb
echo Launching with CDB debugger...
echo.
echo CDB Commands:
echo   bp Mw05Recomp!VdSwap          - Break on VdSwap
echo   bp Mw05Recomp!sub_82598A20    - Break on present callback
echo   g                              - Continue execution
echo   k                              - Show call stack
echo   t                              - Step through
echo   q                              - Quit debugger
echo.
cdb -g -G -o "%EXE%"
goto :eof

:launch_windbg
echo Launching with WinDbg...
echo.
echo WinDbg Commands:
echo   bp Mw05Recomp!VdSwap          - Break on VdSwap
echo   bp Mw05Recomp!sub_82598A20    - Break on present callback
echo   g                              - Continue execution
echo   k                              - Show call stack
echo   t                              - Step through
echo.
windbg -g "%EXE%"
goto :eof

:launch_vdswap
echo Launching with VdSwap debugging enabled...
echo.
echo This will:
echo   - Enable VdSwap tracing
echo   - Enable PM4 tracing
echo   - Set PM4 verbosity to 3
echo   - Log all VdSwap calls to console
echo.
set MW05_DEBUG_PM4=3
set MW05_PM4_TRACE=1
"%EXE%"
goto :eof

:launch_pm4
echo Launching with PM4 debugging enabled...
echo.
echo This will:
echo   - Enable PM4 tracing
echo   - Set PM4 verbosity to 3
echo   - Show PM4 opcode histogram
echo   - Dump PM4 ring buffer
echo.
set MW05_DEBUG_PM4=3
set MW05_PM4_TRACE=1
"%EXE%"
goto :eof

:launch_normal
echo Launching normally...
echo.
echo Press ` (backtick) or F1 to open debug console
echo Type 'help' in console for list of commands
echo.
"%EXE%"
goto :eof

:show_help
echo MW05 Debug Launcher
echo.
echo Usage: debug.cmd [mode]
echo.
echo Modes:
echo   normal  - Launch normally (default)
echo   cdb     - Launch with CDB debugger
echo   windbg  - Launch with WinDbg debugger
echo   vdswap  - Launch with VdSwap debugging enabled
echo   pm4     - Launch with PM4 debugging enabled
echo   help    - Show this help
echo.
echo Examples:
echo   debug.cmd              - Launch normally
echo   debug.cmd cdb          - Launch with CDB
echo   debug.cmd vdswap       - Debug VdSwap calls
echo.
echo Debug Console:
echo   Press ` or F1 to open debug console
echo   Type 'help' for list of commands
echo.
goto :eof

