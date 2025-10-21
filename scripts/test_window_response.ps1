# Test if the window is responding and updating

$env:MW05_FAST_BOOT = "0"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_TRACE_KERNEL = "0"  # Disable tracing to reduce overhead
$env:MW05_HOST_TRACE_IMPORTS = "0"

Write-Host "=== TESTING WINDOW RESPONSIVENESS ===" -ForegroundColor Cyan
Write-Host "Starting game for 10 seconds..." -ForegroundColor Yellow
Write-Host "Try to interact with the window (move it, click it, etc.)" -ForegroundColor Yellow
Write-Host ""

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}
if (Test-Path "test_window_stderr.txt") {
    Remove-Item "test_window_stderr.txt" -Force
}

# Start the game
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -RedirectStandardError "test_window_stderr.txt"

# Wait 10 seconds
Start-Sleep -Seconds 10

# Kill the process
if (!$proc.HasExited) {
    $proc.Kill()
    Write-Host "Process killed after 10 seconds" -ForegroundColor Yellow
}

Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

# Check for Present calls
Write-Host "`nChecking for Present calls in stderr:" -ForegroundColor Green
$presentCalls = Get-Content test_window_stderr.txt | Select-String "VideoPresent|Present"
if ($presentCalls) {
    Write-Host "Found Present-related output:"
    $presentCalls | Select-Object -First 10
} else {
    Write-Host "No Present calls found in stderr" -ForegroundColor Red
}

# Check for window events
Write-Host "`nChecking for SDL/Window events:" -ForegroundColor Green
$windowEvents = Get-Content test_window_stderr.txt | Select-String "SDL|Window|Event"
if ($windowEvents) {
    Write-Host "Found window-related output:"
    $windowEvents | Select-Object -First 10
} else {
    Write-Host "No window events found in stderr" -ForegroundColor Yellow
}

# Check for errors
Write-Host "`nChecking for errors:" -ForegroundColor Green
$errors = Get-Content test_window_stderr.txt | Select-String "ERROR|FAIL|error|fail"
if ($errors) {
    Write-Host "Found errors:"
    $errors | Select-Object -First 10
} else {
    Write-Host "No errors found" -ForegroundColor Green
}

Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Cyan
Write-Host "If the window was unresponsive:"
Write-Host "1. The SDL event loop might be blocked"
Write-Host "2. The main thread might be stuck in a long operation"
Write-Host "3. The window might need explicit refresh/update calls"
Write-Host ""
Write-Host "If the window was responsive:"
Write-Host "1. The issue might be with the rendering, not the event loop"
Write-Host "2. Check if the backbuffer is being cleared/updated"

