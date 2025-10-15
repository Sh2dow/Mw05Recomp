# Pure natural test - NO workarounds, let game run completely naturally
# This will likely hang or crash, but will show us what's actually broken

Write-Host "=== MW05 PURE NATURAL TEST ===" -ForegroundColor Cyan
Write-Host "Running with ZERO workarounds - game will run completely naturally."
Write-Host "This will likely hang or crash, showing us what's actually broken."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# Disable ALL workarounds
$env:MW05_UNBLOCK_MAIN = "0"
$env:MW05_BREAK_82813514 = "0"
$env:MW05_FAKE_ALLOC_SYSBUF = "0"
$env:MW05_FAST_BOOT = "0"
$env:MW05_BREAK_WAIT_LOOP = "0"
$env:MW05_FORCE_VD_INIT = "0"
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"
$env:MW05_FORCE_RENDER_THREAD = "0"
$env:MW05_FORCE_PRESENT = "0"
$env:MW05_FORCE_GRAPHICS_INIT = "0"
$env:MW05_BREAK_CRT_INIT = "0"
$env:MW05_BREAK_8262DD80 = "0"
$env:MW05_FORCE_SLEEP_CALL = "0"

# Enable tracing to see what happens
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}

Write-Host "Starting game with pure natural behavior..." -ForegroundColor Yellow
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
    
    Write-Host "`nLast 20 trace lines:"
    Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-Object -Last 20
}

