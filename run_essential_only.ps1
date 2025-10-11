# Essential only test - ONLY the workarounds that prevent hangs/crashes
# Based on analysis, these are truly essential:
# - MW05_BREAK_82813514: Breaks worker thread infinite loop (ESSENTIAL)
# - MW05_FAKE_ALLOC_SYSBUF: Provides fallback when allocator callback is NULL (ESSENTIAL)

Write-Host "=== MW05 ESSENTIAL ONLY TEST ===" -ForegroundColor Cyan
Write-Host "Running with ONLY essential workarounds to prevent hangs/crashes."
Write-Host "All other workarounds disabled to allow natural game behavior."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# ESSENTIAL workarounds (prevent hangs/crashes)
$env:MW05_BREAK_82813514 = "1"           # Break worker thread infinite loop
$env:MW05_FAKE_ALLOC_SYSBUF = "1"        # Fake system buffer allocation when callback is NULL

# Disable all non-essential workarounds
$env:MW05_UNBLOCK_MAIN = "0"             # Let game manage its own main thread
$env:MW05_FAST_BOOT = "0"                # No fast boot
$env:MW05_BREAK_WAIT_LOOP = "0"          # Let game wait naturally
$env:MW05_FORCE_VD_INIT = "0"            # Let game initialize graphics naturally
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"      # Let game register callbacks naturally
$env:MW05_FORCE_RENDER_THREAD = "0"      # Let game create render thread naturally
$env:MW05_FORCE_PRESENT = "0"            # Let game present naturally
$env:MW05_FORCE_GRAPHICS_INIT = "0"      # Let game init graphics naturally
$env:MW05_BREAK_CRT_INIT = "0"           # Let CRT init run naturally
$env:MW05_BREAK_8262DD80 = "0"           # Let string formatting run naturally
$env:MW05_FORCE_SLEEP_CALL = "0"         # Let sleep calls happen naturally

# Enable tracing
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}

Write-Host "Starting game with essential workarounds only..." -ForegroundColor Yellow
Write-Host ""

# Run the game
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    $lineCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Measure-Object -Line).Lines
    Write-Host "Trace log lines: $lineCount"
    
    $threadCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "ExCreateThread DONE").Count
    Write-Host "Threads created: $threadCount"
    
    $fileIoCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "NtCreateFile|NtOpenFile|NtReadFile").Count
    Write-Host "File I/O calls: $fileIoCount"
    
    Write-Host "`nFirst 10 ExCreateThread calls:"
    Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "ExCreateThread DONE" | Select-Object -First 10
    
    Write-Host "`nFirst 5 file I/O calls (if any):"
    Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "NtCreateFile|NtOpenFile|NtReadFile" | Select-Object -First 5
}

