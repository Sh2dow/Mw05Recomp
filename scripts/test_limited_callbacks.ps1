# Test with limited callback invocations to see if crash still occurs

$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"  # Every 10 ticks
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "3"  # Stop after 3 invocations

Write-Host "Testing with limited callback invocations (max 3)..." -ForegroundColor Cyan
Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $env:MW05_FORCE_GFX_NOTIFY_CB"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_CTX = $env:MW05_FORCE_GFX_NOTIFY_CB_CTX"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = $env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS"
Write-Host "  MW05_GFX_CALLBACK_FREQUENCY = $env:MW05_GFX_CALLBACK_FREQUENCY"
Write-Host "  MW05_GFX_CALLBACK_MAX_INVOCATIONS = $env:MW05_GFX_CALLBACK_MAX_INVOCATIONS"
Write-Host ""
Write-Host "If crash still occurs around tick 400, it proves the crash is NOT caused by the callback." -ForegroundColor Magenta

$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow
Write-Host "Game started (PID: $($proc.Id)). Running for 20 seconds..." -ForegroundColor Green

Start-Sleep -Seconds 20

if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host ""
Write-Host "Test complete!" -ForegroundColor Cyan

