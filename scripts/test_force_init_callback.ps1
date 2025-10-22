# Test script to enable force-initialization of callback parameter structure
# This script sets MW05_FORCE_INIT_CALLBACK_PARAM environment variable and runs the game

Write-Host "[TEST] Enabling force-initialization of callback parameter structure..." -ForegroundColor Yellow
$env:MW05_FORCE_INIT_CALLBACK_PARAM = "0"
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_HOST_TRACE_FILE = "traces/force_init_test_trace.log"

Write-Host "[TEST] Environment variables set:" -ForegroundColor Green
Write-Host "  MW05_FORCE_INIT_CALLBACK_PARAM = $env:MW05_FORCE_INIT_CALLBACK_PARAM"
Write-Host "  MW05_STREAM_BRIDGE = $env:MW05_STREAM_BRIDGE"
Write-Host "  MW05_HOST_TRACE_FILE = $env:MW05_HOST_TRACE_FILE"

Write-Host "`n[TEST] Running game for 60 seconds..." -ForegroundColor Yellow
python scripts/auto_handle_messageboxes.py --duration 60

Write-Host "`n[TEST] Checking results..." -ForegroundColor Yellow

# Check if callback parameter was initialized
$initMessages = Get-Content traces/auto_test_stderr.txt | Select-String "FORCE-INITIALIZING callback parameter|Callback parameter structure IS initialized"
if ($initMessages) {
    Write-Host "[SUCCESS] Callback parameter structure was initialized!" -ForegroundColor Green
    $initMessages | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "[FAIL] Callback parameter structure was NOT initialized" -ForegroundColor Red
}

# Check how many threads were created
$threadMessages = Get-Content traces/auto_test_stderr.txt | Select-String "Thread #[0-9]+ created"
Write-Host "`n[THREADS] Threads created:" -ForegroundColor Yellow
$threadMessages | ForEach-Object { Write-Host "  $_" }

# Check for worker thread creation
$workerMessages = Get-Content traces/auto_test_stderr.txt | Select-String "Creating missing worker threads|Creating worker thread"
if ($workerMessages) {
    Write-Host "`n[WORKERS] Worker thread creation:" -ForegroundColor Green
    $workerMessages | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "`n[WORKERS] No worker thread creation messages found" -ForegroundColor Red
}

Write-Host "`n[TEST] Test complete!" -ForegroundColor Green

