# Test WITHOUT forced callback registration
# Let the game initialize graphics naturally

# Remove all forced callback environment variables
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB -ErrorAction SilentlyContinue
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB_CTX -ErrorAction SilentlyContinue
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS -ErrorAction SilentlyContinue
Remove-Item Env:MW05_GFX_CALLBACK_FREQUENCY -ErrorAction SilentlyContinue
Remove-Item Env:MW05_GFX_CALLBACK_MAX_INVOCATIONS -ErrorAction SilentlyContinue
Remove-Item Env:MW05_DISABLE_CALLBACK_INVOCATION -ErrorAction SilentlyContinue

Write-Host "Testing WITHOUT forced callback registration" -ForegroundColor Cyan
Write-Host "Letting the game initialize graphics naturally" -ForegroundColor Cyan

& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`nExit code: $LASTEXITCODE" -ForegroundColor Yellow

