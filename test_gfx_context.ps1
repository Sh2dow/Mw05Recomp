# Test script to run the game with graphics context allocation
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"  # Delay callback REGISTRATION until after video init at tick 300
$env:MW05_GUEST_ISR_DELAY_TICKS = "0"  # No additional delay for callback invocation

Write-Host "Testing graphics context allocation..." -ForegroundColor Cyan
Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $env:MW05_FORCE_GFX_NOTIFY_CB" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_CTX = $env:MW05_FORCE_GFX_NOTIFY_CB_CTX" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = $env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS (delay registration)" -ForegroundColor Yellow
Write-Host ""

# Run for 15 seconds to allow video init at tick 300 and callback at tick 350
$process = Start-Process -FilePath "out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow

Write-Host "Game started (PID: $($process.Id)). Running for 15 seconds..." -ForegroundColor Green

Start-Sleep -Seconds 15

if (!$process.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    $process.Kill()
    $process.WaitForExit()
}

Write-Host ""
Write-Host "Test complete. Check the output above for:" -ForegroundColor Cyan
Write-Host "  [GFX-CTX] SUCCESS: Allocated and zeroed..." -ForegroundColor Green
Write-Host "  HOST.GfxContext.allocated_and_zeroed..." -ForegroundColor Green
Write-Host ""
Write-Host "If you see these messages, the context was successfully allocated!" -ForegroundColor Cyan

