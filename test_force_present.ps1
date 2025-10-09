# Test Option A: Force Present from Host
# This will make the host continuously present frames regardless of VdSwap calls

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OPTION A: FORCE PRESENT TEST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test will enable host-driven present to bypass the game's present logic." -ForegroundColor Yellow
Write-Host "If we see graphics, it means rendering is working and the issue is just VdSwap." -ForegroundColor Yellow
Write-Host ""

# Enable force present
$env:MW05_FORCE_PRESENT = "1"

Write-Host "Environment variables set:" -ForegroundColor Green
Write-Host "  MW05_FORCE_PRESENT=1" -ForegroundColor Green
Write-Host ""
Write-Host "Starting game..." -ForegroundColor Green
Write-Host "The game will run for 30 seconds." -ForegroundColor Yellow
Write-Host "WATCH THE SCREEN - Do you see any graphics?" -ForegroundColor Yellow
Write-Host ""

# Run for 30 seconds
$process = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru

Write-Host "Game running (PID: $($process.Id))" -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OBSERVATION CHECKLIST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[ ] Do you see a window?" -ForegroundColor Yellow
Write-Host "[ ] Is the window black or showing graphics?" -ForegroundColor Yellow
Write-Host "[ ] Do you see any UI elements?" -ForegroundColor Yellow
Write-Host "[ ] Do you see any 3D geometry?" -ForegroundColor Yellow
Write-Host "[ ] Do you see any textures?" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Waiting 30 seconds..." -ForegroundColor Yellow

Start-Sleep -Seconds 30

Write-Host "`nStopping game..." -ForegroundColor Yellow
Stop-Process -Id $process.Id -Force

Write-Host "`nTest complete!" -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "If you saw graphics:" -ForegroundColor Green
Write-Host "  - Rendering is working!" -ForegroundColor Green
Write-Host "  - The issue is that the game isn't calling VdSwap" -ForegroundColor Green
Write-Host "  - Next step: Investigate why game isn't calling VdSwap (Option B)" -ForegroundColor Green
Write-Host ""
Write-Host "If you saw a black screen:" -ForegroundColor Red
Write-Host "  - There are deeper rendering issues" -ForegroundColor Red
Write-Host "  - Need to investigate render target setup, video mode, etc." -ForegroundColor Red
Write-Host ""

