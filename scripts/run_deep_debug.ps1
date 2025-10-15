# Deep debugging script - enables detailed tracing and analysis
# This will help us find exactly where the game is stuck

# Enable deep debugging mode
$env:MW05_DEEP_DEBUG = "1"

# Essential boot shims
$env:MW05_BREAK_82813514 = "1"                           # Break worker thread infinite loop
$env:MW05_FAKE_ALLOC_SYSBUF = "1"                        # Fake system buffer allocation
$env:MW05_UNBLOCK_MAIN = "1"                             # Unblock main thread

# Enable comprehensive tracing
$env:MW05_TRACE_KERNEL = "1"                             # Enable kernel tracing
$env:MW05_HOST_TRACE_IMPORTS = "1"                       # Enable import tracing to file
$env:MW05_TRACE_HEAP = "1"                               # Enable heap tracing
$env:MW05_TITLE_STATE_TRACE = "1"                        # Enable title state tracing

# Sleep loop control
$env:MW05_BREAK_SLEEP_LOOP = "1"
$env:MW05_BREAK_SLEEP_AFTER = "5"

# Graphics initialization
$env:MW05_FORCE_VD_INIT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"

# Disable aggressive interventions that might hide the problem
$env:MW05_VBLANK_VDSWAP = "0"
$env:MW05_KICK_VIDEO = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"
$env:MW05_FORCE_PRESENT = "0"
$env:MW05_FORCE_PRESENT_BG = "0"
$env:MW05_VDSWAP_NOTIFY = "0"
$env:MW05_FAST_BOOT = "0"
$env:MW05_FAST_RET = "0"

Write-Host "=== MW05 DEEP DEBUGGING SESSION ===" -ForegroundColor Cyan
Write-Host "This will run the game for 60 seconds with detailed tracing enabled."
Write-Host "Press Ctrl+C to stop early if needed."
Write-Host ""

# Clean up old logs
if (Test-Path ".\debug_stderr.txt") {
    Remove-Item ".\debug_stderr.txt" -Force
}
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}

Write-Host "Starting game..." -ForegroundColor Yellow
$startTime = Get-Date

$p = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" `
                   -PassThru `
                   -RedirectStandardError ".\debug_stderr.txt"

# Wait for 60 seconds
Start-Sleep -Seconds 60

Write-Host "Stopping game..." -ForegroundColor Yellow
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host ""
Write-Host "=== RUN COMPLETE ===" -ForegroundColor Green
Write-Host "Duration: $([math]::Round($duration, 2)) seconds"
Write-Host ""

# Quick analysis
Write-Host "=== QUICK ANALYSIS ===" -ForegroundColor Cyan

# Check if trace log exists
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    $traceLog = ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log"
    
    $totalLines = (Get-Content $traceLog).Count
    Write-Host "Trace log lines: $totalLines" -ForegroundColor White
    
    $fileIoCount = (Get-Content $traceLog | Select-String 'NtCreateFile|NtOpenFile|NtReadFile').Count
    Write-Host "File I/O operations: $fileIoCount" -ForegroundColor $(if ($fileIoCount -eq 0) { "Red" } else { "Green" })
    
    $sleepCount = (Get-Content $traceLog | Select-String 'KeDelayExecutionThread').Count
    Write-Host "Sleep calls: $sleepCount" -ForegroundColor White
    
    $frameUpdateCount = (Get-Content $traceLog | Select-String 'sub_8262DE60').Count
    Write-Host "Frame updates: $frameUpdateCount" -ForegroundColor White
    
    $sub82595FC8Count = (Get-Content $traceLog | Select-String 'sub_82595FC8').Count
    Write-Host "sub_82595FC8 calls: $sub82595FC8Count" -ForegroundColor White
    
    Write-Host ""
    Write-Host "Sample of recent frame updates:" -ForegroundColor Cyan
    Get-Content $traceLog | Select-String 'sub_8262DE60.called' | Select-Object -Last 5
    
} else {
    Write-Host "WARNING: Trace log not found!" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== STDERR OUTPUT ===" -ForegroundColor Cyan
if (Test-Path ".\debug_stderr.txt") {
    $stderrLines = Get-Content ".\debug_stderr.txt" -ErrorAction SilentlyContinue
    Write-Host "Total stderr lines: $($stderrLines.Count)" -ForegroundColor White
    
    $renderDebugLines = $stderrLines | Select-String "RENDER-DEBUG"
    if ($renderDebugLines) {
        Write-Host "Render debug messages: $($renderDebugLines.Count)" -ForegroundColor White
        Write-Host "Sample:" -ForegroundColor Cyan
        $renderDebugLines | Select-Object -First 10
    }
} else {
    Write-Host "WARNING: stderr log not found!" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== RUNNING PYTHON ANALYSIS ===" -ForegroundColor Cyan
Write-Host "This will analyze the trace log in detail..."
Write-Host ""

# Run the Python analysis script
if (Test-Path ".\tools\deep_debug_trace.py") {
    python ".\tools\deep_debug_trace.py"
} else {
    Write-Host "WARNING: Python analysis script not found!" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== DEBUGGING SESSION COMPLETE ===" -ForegroundColor Green
Write-Host "Logs saved to:"
Write-Host "  - debug_stderr.txt"
Write-Host "  - out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Review the analysis output above"
Write-Host "  2. Check for file I/O - if 0, game is stuck before asset loading"
Write-Host "  3. Look at the execution hotspots to see where time is spent"
Write-Host "  4. Check the blocking point analysis for recommendations"
Write-Host ""

