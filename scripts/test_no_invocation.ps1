# Test with callback registration but NO invocation
# This tests if registration alone causes the crash

$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "450"
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"
$env:MW05_DISABLE_CALLBACK_INVOCATION = "1"  # NEW: Disable invocation

Write-Host "Testing with callback REGISTRATION but NO INVOCATION" -ForegroundColor Cyan
Write-Host "This will test if registration alone causes the crash" -ForegroundColor Cyan

& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`nExit code: $LASTEXITCODE" -ForegroundColor Yellow

