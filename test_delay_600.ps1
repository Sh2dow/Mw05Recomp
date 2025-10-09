# Test with callback registration delayed to tick 600
# This tests if the game needs more time to initialize systems

$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "600"  # Delay until tick 600
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"  # 0 = unlimited

Write-Host "Testing with callback registration delayed to tick 600 (150 ticks later than before)" -ForegroundColor Cyan
Write-Host "This will test if the game needs more time to initialize systems" -ForegroundColor Cyan

& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`nExit code: $LASTEXITCODE" -ForegroundColor Yellow

