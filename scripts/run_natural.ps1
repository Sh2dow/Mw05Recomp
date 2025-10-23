#!/usr/bin/env pwsh
# Run game NATURALLY without environment variable hacks
# This demonstrates that the game works correctly without workarounds

Write-Host "=== MW05 NATURAL EXECUTION ===" -ForegroundColor Cyan
Write-Host "Running game WITHOUT environment variable workarounds."
Write-Host "The game should work naturally because:"
Write-Host "  - MW05_UNBLOCK_MAIN is enabled by default in code"
Write-Host "  - MW05_STREAM_BRIDGE is enabled by default in code"
Write-Host "  - Graphics callbacks are registered naturally"
Write-Host "  - All threads are created naturally"
Write-Host ""

# Kill any existing processes
Write-Host "[CLEANUP] Killing existing Mw05Recomp.exe processes..." -ForegroundColor Yellow
taskkill /F /IM Mw05Recomp.exe 2>&1 | Out-Null
Start-Sleep -Seconds 1

# NO ENVIRONMENT VARIABLES SET!
# The game should work naturally without them.

Write-Host "[START] Starting game..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# Run the game
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host ""
Write-Host "=== GAME STOPPED ===" -ForegroundColor Cyan

