# Quick test to see import table processing output
$env:MW05_BREAK_82813514 = "1"
$env:MW05_FAKE_ALLOC_SYSBUF = "1"

Write-Host "Starting game to test import table processing..." -ForegroundColor Cyan
Write-Host "Will run for 3 seconds then kill" -ForegroundColor Yellow
Write-Host ""

# Start the game in background
$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -RedirectStandardError "import_test_stderr.txt"

# Wait 3 seconds
Start-Sleep -Seconds 3

# Kill it
Stop-Process -Id $proc.Id -Force

# Show the import table output
Write-Host "`n=== Import Table Output ===" -ForegroundColor Cyan
Get-Content "import_test_stderr.txt" | Select-String "\[XEX\]" | Select-Object -First 30

