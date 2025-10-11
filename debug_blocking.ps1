# Debug script to find what's blocking the game from issuing draws

$env:MW05_FAST_BOOT = "1"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

Write-Host "=== DEBUGGING WHAT'S BLOCKING DRAWS ===" -ForegroundColor Cyan
Write-Host "Running game for 30 seconds with full tracing..." -ForegroundColor Yellow

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}
if (Test-Path "debug_blocking_stderr.txt") {
    Remove-Item "debug_blocking_stderr.txt" -Force
}

# Start the game
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -RedirectStandardError "debug_blocking_stderr.txt"

# Wait 30 seconds
Start-Sleep -Seconds 30

# Kill the process
if (!$proc.HasExited) {
    $proc.Kill()
    Write-Host "Process killed after 30 seconds" -ForegroundColor Yellow
}

Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

# Check import table
Write-Host "`n1. Import Table Status:" -ForegroundColor Green
Get-Content debug_blocking_stderr.txt | Select-String "Import table processing complete"

# Check for draws
Write-Host "`n2. Draw Commands:" -ForegroundColor Green
$draws = Get-Content debug_blocking_stderr.txt | Select-String "draws=" | Select-Object -Last 5
if ($draws) {
    $draws
    $nonZeroDraws = Get-Content debug_blocking_stderr.txt | Select-String "draws=[1-9]"
    if ($nonZeroDraws) {
        Write-Host "FOUND NON-ZERO DRAWS!" -ForegroundColor Green
    } else {
        Write-Host "All draws are zero - game is not issuing draw commands" -ForegroundColor Red
    }
} else {
    Write-Host "No PM4 scan results found" -ForegroundColor Red
}

# Check graphics callbacks
Write-Host "`n3. Graphics Callbacks:" -ForegroundColor Green
$callbackCount = (Get-Content debug_blocking_stderr.txt | Select-String "GFX-CALLBACK.*returned successfully").Count
Write-Host "Total graphics callbacks: $callbackCount"

# Check for missing imports that are being called
Write-Host "`n4. Top 20 Missing Imports Being Called:" -ForegroundColor Green
$missing = Get-Content debug_blocking_stderr.txt | Select-String "NOT IMPLEMENTED" | ForEach-Object {
    if ($_ -match '__imp__([A-Za-z0-9_]+)') {
        $matches[1]
    }
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 20
$missing | Format-Table Name, Count -AutoSize

# Check trace log if it exists
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Write-Host "`n5. Trace Log Analysis:" -ForegroundColor Green
    $traceLines = Get-Content ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log"
    Write-Host "Total trace lines: $($traceLines.Count)"
    
    # Check for file I/O
    $fileIo = $traceLines | Select-String "NtCreateFile|NtOpenFile|NtReadFile|NtWriteFile"
    Write-Host "File I/O operations: $($fileIo.Count)"
    if ($fileIo.Count -gt 0) {
        Write-Host "Sample file I/O operations:"
        $fileIo | Select-Object -First 10
    }
    
    # Check for thread activity
    $threads = $traceLines | Select-String "CreateThread|ExCreateThread"
    Write-Host "`nThread creations: $($threads.Count)"
    
    # Check for synchronization
    $sync = $traceLines | Select-String "WaitForSingleObject|WaitForMultipleObjects|NtWaitForSingleObject"
    Write-Host "Synchronization waits: $($sync.Count)"
    
    # Check for Xam calls
    $xam = $traceLines | Select-String "Xam"
    Write-Host "Xam* function calls: $($xam.Count)"
    
    # Look for errors or failures
    $errors = $traceLines | Select-String "ERROR|FAIL|INVALID"
    Write-Host "Errors/Failures: $($errors.Count)"
    if ($errors.Count -gt 0) {
        Write-Host "Sample errors:"
        $errors | Select-Object -First 10
    }
}

Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Cyan
Write-Host "Based on the analysis above, the next steps should be:"
Write-Host "1. Implement the most frequently called missing imports"
Write-Host "2. Check if file I/O is failing (game might be waiting for resources)"
Write-Host "3. Check if threads are blocked on synchronization primitives"
Write-Host "4. Investigate Xam* function failures (UI/content system)"

