# Test graphics callback with slower frequency (every 10 ticks = 6Hz instead of 60Hz)

$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"  # Delay callback REGISTRATION until after video init at tick 300
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"  # Call every 10 ticks (6Hz instead of 60Hz)

Write-Host "Testing graphics callback with slower frequency (every 10 ticks)..." -ForegroundColor Cyan
Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $env:MW05_FORCE_GFX_NOTIFY_CB"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_CTX = $env:MW05_FORCE_GFX_NOTIFY_CB_CTX"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = $env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS (delay registration)"
Write-Host "  MW05_GFX_CALLBACK_FREQUENCY = $env:MW05_GFX_CALLBACK_FREQUENCY (call every 10 ticks = 6Hz)"

$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow
Write-Host "Game started (PID: $($proc.Id)). Running for 20 seconds..." -ForegroundColor Green

Start-Sleep -Seconds 20

if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host "Test complete. Check the output above for:" -ForegroundColor Cyan
Write-Host "  [GFX-CTX] SUCCESS: Allocated and zeroed..." -ForegroundColor Green
Write-Host "  HOST.GfxContext.allocated_and_zeroed..." -ForegroundColor Green
Write-Host ""
Write-Host "If you see these messages, the context was successfully allocated!" -ForegroundColor Cyan

