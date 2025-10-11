# Minimal test - only essential fixes, no aggressive interventions
# This should allow the game to run naturally and show what's actually broken

# ESSENTIAL: These are required for the game to boot at all
$env:MW05_BREAK_82813514 = "1"           # Break worker thread infinite loop (ESSENTIAL)
$env:MW05_FAKE_ALLOC_SYSBUF = "1"        # Fake system buffer allocation (ESSENTIAL)

# Enable tracing to see what's happening
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

# Disable all aggressive interventions
$env:MW05_UNBLOCK_MAIN = "0"             # Let the game manage its own main thread
$env:MW05_BREAK_SLEEP_LOOP = "0"         # Let the game sleep naturally
$env:MW05_FORCE_VD_INIT = "0"            # Let the game initialize graphics naturally
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"      # Let the game register callbacks naturally
$env:MW05_FORCE_RENDER_THREAD = "0"      # Let the game create render thread naturally
$env:MW05_FORCE_PRESENT = "1"            # Force Present to avoid stale image
$env:MW05_FORCE_PRESENT_BG = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"
$env:MW05_FORCE_PRESENT_EVERY_ZERO = "0"
$env:MW05_FORCE_PRESENT_ON_ZERO = "0"
$env:MW05_FORCE_PRESENT_ON_FIRST_ZERO = "0"
$env:MW05_ISR_CALL_PRESENT = "0"
$env:MW05_FAST_BOOT = "0"
$env:MW05_FAST_RET = "0"

Write-Host "=== MW05 MINIMAL TEST ===" -ForegroundColor Cyan
Write-Host "Running with only essential fixes, no aggressive interventions."
Write-Host "This will show what the game actually does naturally."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}

# Run the game and let it run until user stops it
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    $lineCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Measure-Object -Line).Lines
    Write-Host "Trace log lines: $lineCount"
    
    $xamNotifyCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "XamNotifyCreateListener").Count
    Write-Host "XamNotifyCreateListener calls: $xamNotifyCount"
    
    $fileIoCount = (Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "NtCreateFile|NtOpenFile|NtReadFile").Count
    Write-Host "File I/O calls: $fileIoCount"
    
    Write-Host "`nFirst 20 XamNotifyCreateListener calls:"
    Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" | Select-String "XamNotifyCreateListener" | Select-Object -First 20
}

