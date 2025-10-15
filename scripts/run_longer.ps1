# Test script to run the game for 30 seconds to see if draws eventually appear

$env:MW05_FAST_BOOT = "1"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"

Write-Host "Starting game for 30 seconds to check for draw commands..." -ForegroundColor Cyan

# Start the game
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -RedirectStandardError "long_run_stderr.txt"

# Wait 30 seconds
Start-Sleep -Seconds 30

# Kill the process
if (!$proc.HasExited) {
    $proc.Kill()
    Write-Host "Process killed after 30 seconds" -ForegroundColor Yellow
}

Write-Host "`n=== Checking for draw commands ===" -ForegroundColor Cyan
$draws = Get-Content long_run_stderr.txt | Select-String "draws=" | Select-Object -Last 10
if ($draws) {
    $draws
} else {
    Write-Host "No PM4 scan results found" -ForegroundColor Red
}

Write-Host "`n=== Checking for any non-zero draws ===" -ForegroundColor Cyan
$nonZeroDraws = Get-Content long_run_stderr.txt | Select-String "draws=[1-9]"
if ($nonZeroDraws) {
    Write-Host "FOUND DRAWS!" -ForegroundColor Green
    $nonZeroDraws | Select-Object -First 20
} else {
    Write-Host "No non-zero draws found yet" -ForegroundColor Yellow
}

Write-Host "`n=== Checking PM4 scan count ===" -ForegroundColor Cyan
$scanCount = (Get-Content long_run_stderr.txt | Select-String "PM4_ScanLinear called").Count
Write-Host "Total PM4 scans: $scanCount" -ForegroundColor Cyan

Write-Host "`n=== Checking for Present calls ===" -ForegroundColor Cyan
Get-Content long_run_stderr.txt | Select-String "Present|PRESENT" | Select-Object -First 10

