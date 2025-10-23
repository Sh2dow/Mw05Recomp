#!/usr/bin/env pwsh
# Test script with proper environment variables and timeout

Write-Host "=== MW05 TEST WITH WORKAROUND ===" -ForegroundColor Cyan

# Kill any existing processes
Write-Host "[CLEANUP] Killing existing Mw05Recomp.exe processes..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -like '*Mw05Recomp*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Start auto message box handler
Write-Host "[HANDLER] Starting auto_handle_messageboxes.py..." -ForegroundColor Yellow
$handler_job = Start-Job -ScriptBlock { python scripts/auto_handle_messageboxes.py }
Start-Sleep -Seconds 1

# Set environment variables
Write-Host "[ENV] Setting environment variables..." -ForegroundColor Yellow
$env:MW05_GAME_PATH = 'out/build/x64-Clang-Debug/Mw05Recomp/game'
$env:MW05_VBLANK_CB = '0'           # Disable guest ISR callback to prevent VBLANK pump from getting stuck
$env:MW05_FORCE_SLEEP_CALL = '0'    # Disable forced sleep call in sub_8262DE60
$env:MW05_DISABLE_SLEEP = '0'       # Don't disable sleep - let it work normally
$env:MW05_SET_FLAG_FROM_SLEEP = '1' # CRITICAL: Enable setting main loop flag from sleep function

Write-Host "  MW05_GAME_PATH = $env:MW05_GAME_PATH" -ForegroundColor Gray
Write-Host "  MW05_VBLANK_CB = $env:MW05_VBLANK_CB" -ForegroundColor Gray
Write-Host "  MW05_FORCE_SLEEP_CALL = $env:MW05_FORCE_SLEEP_CALL" -ForegroundColor Gray
Write-Host "  MW05_DISABLE_SLEEP = $env:MW05_DISABLE_SLEEP" -ForegroundColor Gray
Write-Host "  MW05_SET_FLAG_FROM_SLEEP = $env:MW05_SET_FLAG_FROM_SLEEP" -ForegroundColor Gray
Write-Host ""

# Start the game
Write-Host "[START] Starting game for 60 seconds..." -ForegroundColor Green
$proc = Start-Process -FilePath 'out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe' -PassThru -NoNewWindow

# Wait for timeout
$timeout = 60
Write-Host "[WAIT] Waiting $timeout seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds $timeout

# Stop the game
Write-Host "[STOP] Stopping game..." -ForegroundColor Yellow
if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Stop the handler
Write-Host "[CLEANUP] Stopping auto_handle_messageboxes.py..." -ForegroundColor Yellow
Stop-Job -Job $handler_job -ErrorAction SilentlyContinue
Remove-Job -Job $handler_job -ErrorAction SilentlyContinue

# Analyze results
Write-Host ""
Write-Host "=== RESULTS ===" -ForegroundColor Cyan

$log_file = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
if (Test-Path $log_file) {
    $log_size_mb = [math]::Round((Get-Item $log_file).Length / 1MB, 2)
    Write-Host "[LOG] Trace log size: $log_size_mb MB" -ForegroundColor Green

    # Check for heap allocation
    $content = Get-Content $log_file -Tail 5000
    $heap_lines = $content | Select-String "Heap Allocated:"
    if ($heap_lines) {
        $last_heap = $heap_lines | Select-Object -Last 1
        Write-Host "[HEAP] $last_heap" -ForegroundColor Green
    }

    # Check for draws
    $draw_lines = $content | Select-String "draws="
    if ($draw_lines) {
        $last_draw = $draw_lines | Select-Object -Last 1
        Write-Host "[DRAWS] $last_draw" -ForegroundColor $(if ($last_draw -match "draws=0") { "Yellow" } else { "Green" })
    }

    # Check for sleep function calls
    $sleep_calls = ($content | Select-String "sub_8262D9D0").Count
    Write-Host "[SLEEP] sub_8262D9D0 calls: $sleep_calls" -ForegroundColor $(if ($sleep_calls -gt 1000) { "Red" } else { "Green" })

    # Check for main loop flag setting
    $flag_sets = ($content | Select-String "set_main_loop_flag").Count
    Write-Host "[FLAG] Main loop flag sets: $flag_sets" -ForegroundColor $(if ($flag_sets -gt 0) { "Green" } else { "Red" })

    # Check for PM4 commands
    $pm4_lines = $content | Select-String "PM4\.Scan"
    if ($pm4_lines) {
        $pm4_count = $pm4_lines.Count
        Write-Host "[PM4] PM4 scan operations: $pm4_count" -ForegroundColor Green
    }

    # Check for VdSwap calls
    $vdswap_lines = $content | Select-String "VdSwap"
    if ($vdswap_lines) {
        $vdswap_count = $vdswap_lines.Count
        Write-Host "[VDSWAP] VdSwap calls: $vdswap_count" -ForegroundColor Green
    }
} else {
    Write-Host "[ERROR] Trace log not found: $log_file" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== TEST COMPLETE ===" -ForegroundColor Cyan
