# Test script to run the game WITHOUT forced graphics callback
# This will help us determine if the crash is related to the graphics callback or something else

Write-Host "Testing game WITHOUT forced graphics callback..." -ForegroundColor Cyan
Write-Host "This will run for 15 seconds to see if it crashes at the same location." -ForegroundColor Yellow
Write-Host ""

# Don't set MW05_FORCE_GFX_NOTIFY_CB
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"

$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

if (!(Test-Path $exePath)) {
    Write-Host "ERROR: Executable not found at $exePath" -ForegroundColor Red
    exit 1
}

Write-Host "Game started. Running for 15 seconds..." -ForegroundColor Green

$proc = Start-Process -FilePath $exePath -PassThru

Start-Sleep -Seconds 15

if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Write-Host "Game stopped normally (no crash)" -ForegroundColor Green
} else {
    Write-Host "Game exited/crashed during test" -ForegroundColor Red
    Write-Host "Exit code: $($proc.ExitCode)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Test complete." -ForegroundColor Cyan

