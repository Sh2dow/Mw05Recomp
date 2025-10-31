# Test StreamBridge file I/O system
# Enable StreamBridge with relaxed LR checking to see if game is trying to load files

Write-Host "[TEST] StreamBridge File I/O Test" -ForegroundColor Cyan
Write-Host ""

# Enable StreamBridge with ANY link register (bypass LR check)
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_STREAM_ANY_LR = "1"
$env:MW05_STREAM_FALLBACK_BOOT = "1"
$env:MW05_STREAM_ACK_NO_PATH = "1"

# Enable debug logging
$env:MW05_DEBUG_FILEIO = "1"
$env:MW05_DEBUG_KERNEL = "1"

Write-Host "[OK] StreamBridge enabled with relaxed LR checking" -ForegroundColor Green
Write-Host "[OK] Debug logging enabled" -ForegroundColor Green
Write-Host ""

# Build
Write-Host "[BUILD] Building..." -ForegroundColor Yellow
.\build_cmd.ps1 -Stage app
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[TEST] Running game for 30 seconds..." -ForegroundColor Yellow
Write-Host ""

# Run test
python scripts/auto_handle_messageboxes.py --duration 30

Write-Host ""
Write-Host "[RESULTS] Checking for StreamBridge activity..." -ForegroundColor Cyan
Write-Host ""

# Check for StreamBridge activity
$streamBridgeLines = Get-Content traces/auto_test_stderr.txt | Select-String -Pattern "StreamBridge|HOST\.Stream" -CaseSensitive
if ($streamBridgeLines) {
    Write-Host "[SUCCESS] StreamBridge activity detected!" -ForegroundColor Green
    Write-Host ""
    $streamBridgeLines | Select-Object -First 20
} else {
    Write-Host "[FAIL] NO StreamBridge activity - game is not trying to load files!" -ForegroundColor Red
}

Write-Host ""
Write-Host "[RESULTS] Checking for sentinel writes (0x0A000000)..." -ForegroundColor Cyan
Write-Host ""

# Check for sentinel writes
$sentinelLines = Get-Content traces/auto_test_stderr.txt | Select-String -Pattern "val=0A000000|sentinel" -CaseSensitive
if ($sentinelLines) {
    Write-Host "[INFO] Sentinel writes detected:" -ForegroundColor Yellow
    Write-Host ""
    $sentinelLines | Select-Object -First 20
} else {
    Write-Host "[INFO] NO sentinel writes detected" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[TEST] Complete!" -ForegroundColor Cyan

