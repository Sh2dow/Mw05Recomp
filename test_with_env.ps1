# Test script with all necessary environment variables
$env:MW05_FAST_BOOT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "500"  # Increased delay to let game initialize

Write-Host "Starting MW05 with environment variables..."
Write-Host "  MW05_FAST_BOOT = $env:MW05_FAST_BOOT"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $env:MW05_FORCE_GFX_NOTIFY_CB"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = $env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS"

$proc = Start-Process -FilePath "out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" `
    -NoNewWindow -PassThru -RedirectStandardError "test_env.txt"

Write-Host "Process started with PID $($proc.Id)"
Write-Host "Running for 30 seconds..."
Start-Sleep -Seconds 30

Write-Host "Stopping process..."
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

Write-Host "`nChecking for crashes..."
$crashes = Get-Content "test_env.txt" | Select-String -Pattern "crash"
if ($crashes) {
    Write-Host "CRASH DETECTED:" -ForegroundColor Red
    $crashes | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "No crashes detected" -ForegroundColor Green
}

Write-Host "`nChecking graphics callback status..."
$cbStatus = Get-Content "test_env.txt" | Select-String -Pattern "VBLANK-ISR-STATUS|GFX-REG" | Select-Object -Last 5
$cbStatus | ForEach-Object { Write-Host "  $_" }

Write-Host "`nChecking thread creation..."
$threads = Get-Content "test_env.txt" | Select-String -Pattern "Thread.*created"
$threads | ForEach-Object { Write-Host "  $_" }

Write-Host "`nChecking draw commands..."
$draws = Get-Content "test_env.txt" | Select-String -Pattern "draws=" | Select-Object -Last 3
$draws | ForEach-Object { Write-Host "  $_" }

Write-Host "`nDone!"

