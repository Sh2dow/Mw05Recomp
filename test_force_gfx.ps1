$env:MW05_FORCE_GRAPHICS_INIT = "1"
./run_with_debug.ps1 2>&1 | Out-Null
Get-Content debug_stderr.txt | Select-String "FORCE_GFX_INIT|VdInitEngines" | Select-Object -First 30

