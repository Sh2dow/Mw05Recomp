# Test script to run the game with import table patching enabled
# Runs for 15 seconds to see if the game progresses past the black screen

$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"

Write-Host "Starting game with import table patching..." -ForegroundColor Cyan
Write-Host "Will run for 15 seconds to check for progress" -ForegroundColor Yellow

# Start the game
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -RedirectStandardError "import_run_stderr.txt"

# Wait 15 seconds
Start-Sleep -Seconds 15

# Kill the process
if (!$proc.HasExited) {
    $proc.Kill()
    Write-Host "Process killed after 15 seconds" -ForegroundColor Yellow
}

Write-Host "`n=== Checking for VdInitializeEngines calls ===" -ForegroundColor Cyan
Get-Content import_run_stderr.txt | Select-String "VdInitializeEngines" | Select-Object -First 10

Write-Host "`n=== Checking for graphics initialization ===" -ForegroundColor Cyan
Get-Content import_run_stderr.txt | Select-String "STUB.*Vd|VD_|graphics" -CaseSensitive:$false | Select-Object -First 20

Write-Host "`n=== Checking for errors ===" -ForegroundColor Cyan
Get-Content import_run_stderr.txt | Select-String "ERROR|FATAL|!!!" | Select-Object -First 10

