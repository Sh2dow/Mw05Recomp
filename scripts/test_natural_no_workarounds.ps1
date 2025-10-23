#!/usr/bin/env pwsh
# Test game with NO workarounds - see what happens naturally

Write-Host "=== TESTING GAME WITH NO WORKAROUNDS ===" -ForegroundColor Cyan
Write-Host "This will show what the game does naturally without environment variable hacks."
Write-Host ""

# Kill any existing processes
taskkill /F /IM Mw05Recomp.exe 2>&1 | Out-Null
Start-Sleep -Seconds 1

# Set ONLY the essential environment variables (not workarounds)
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_HOST_TRACE_FILE = "traces/natural_test_trace.log"

# DISABLE all workarounds
#$env:MW05_UNBLOCK_MAIN = "0"
#$env:MW05_FORCE_GFX_NOTIFY_CB = "0"
#$env:MW05_FORCE_RENDER_THREADS = "0"
#$env:MW05_FORCE_INIT_CALLBACK_PARAM = "0"
#$env:MW05_SET_PRESENT_CB = "0"
#$env:MW05_FORCE_PRESENT = "0"
#$env:MW05_FORCE_VD_INIT = "0"

Write-Host "[ENV] All workarounds DISABLED" -ForegroundColor Yellow
Write-Host "  MW05_UNBLOCK_MAIN = 0"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = 0"
Write-Host "  MW05_FORCE_RENDER_THREADS = 0"
Write-Host "  MW05_FORCE_INIT_CALLBACK_PARAM = 0"
Write-Host "  MW05_SET_PRESENT_CB = 0"
Write-Host "  MW05_FORCE_PRESENT = 0"
Write-Host ""

# Start game and let it run for 30 seconds
Write-Host "[START] Starting game for 30 seconds..." -ForegroundColor Green
$stderr_file = "traces/natural_test_stderr.txt"
$process = Start-Process -FilePath "out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow -RedirectStandardError $stderr_file

Start-Sleep -Seconds 120

Write-Host "[STOP] Stopping game..." -ForegroundColor Yellow
Stop-Process -Id $process.Id -Force 2>&1 | Out-Null
Start-Sleep -Seconds 2

# Analyze results
Write-Host ""
Write-Host "=== RESULTS ===" -ForegroundColor Cyan

if (Test-Path $stderr_file) {
    $lines = Get-Content $stderr_file
    
    # Check for draws
    $draw_lines = $lines | Select-String "draws="
    if ($draw_lines) {
        $last_draw = $draw_lines | Select-Object -Last 1
        Write-Host "[DRAWS] $last_draw" -ForegroundColor Green
    } else {
        Write-Host "[DRAWS] No draw information found" -ForegroundColor Red
    }
    
    # Check for PM4 packets
    $pm4_lines = $lines | Select-String "PM4-TYPE-DIST"
    if ($pm4_lines) {
        $last_pm4 = $pm4_lines | Select-Object -Last 1
        Write-Host "[PM4] $last_pm4" -ForegroundColor Green
    } else {
        Write-Host "[PM4] No PM4 packet information found" -ForegroundColor Red
    }
    
    # Check for file I/O
    $fileio_count = ($lines | Select-String "StreamBridge").Count
    Write-Host "[FILE I/O] StreamBridge operations: $fileio_count" -ForegroundColor $(if ($fileio_count -gt 0) { "Green" } else { "Red" })
    
    # Check for crashes/errors
    $crash_lines = $lines | Select-String "ABORT|Exception|Assertion failed"
    if ($crash_lines) {
        Write-Host "[CRASH] Game crashed!" -ForegroundColor Red
        $crash_lines | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    } else {
        Write-Host "[CRASH] No crashes detected" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Last 20 lines of stderr:" -ForegroundColor Yellow
    $lines | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "[ERROR] Stderr file not found: $stderr_file" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== CONCLUSION ===" -ForegroundColor Cyan
Write-Host "If the game didn't crash and is processing PM4 packets, then it's working naturally!"
Write-Host "If it crashed or got stuck, we need to fix the root cause instead of using workarounds."

