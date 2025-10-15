# Test graphics callback with UNLIMITED invocations
# This tests if the crash is caused by stopping the callback or by the game's normal execution

Write-Host "Testing with UNLIMITED callback invocations..." -ForegroundColor Cyan
Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = 1"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_CTX = 0x40007180"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = 350"
Write-Host "  MW05_GFX_CALLBACK_FREQUENCY = 10"
Write-Host "  MW05_GFX_CALLBACK_MAX_INVOCATIONS = 0 (UNLIMITED)" -ForegroundColor Green
Write-Host ""
Write-Host "If the game runs past tick 400, it proves the callback needs to keep running!" -ForegroundColor Magenta
Write-Host ""

$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"  # 0 = unlimited

$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

Write-Host "Game started (PID: $($proc.Id)). Running for 30 seconds..." -ForegroundColor Green
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow

Start-Sleep -Seconds 30

if (!$proc.HasExited) {
    Write-Host "Stopping game after 30 seconds..." -ForegroundColor Yellow
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host "Test complete!" -ForegroundColor Cyan

