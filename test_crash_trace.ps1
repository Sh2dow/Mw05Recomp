# Test script to capture crash trace output
# Run the game without forced graphics callback and capture the crash trace

Write-Host "Running game to capture crash trace..." -ForegroundColor Cyan
Write-Host "This will run for 15 seconds or until crash." -ForegroundColor Yellow
Write-Host ""

# Don't force graphics callback - let it crash naturally
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"

$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$stderrFile = "crash_trace.txt"

if (!(Test-Path $exePath)) {
    Write-Host "ERROR: Executable not found at $exePath" -ForegroundColor Red
    exit 1
}

# Remove old trace file if it exists
if (Test-Path $stderrFile) {
    Remove-Item $stderrFile
}

Write-Host "Starting game..." -ForegroundColor Green

$proc = Start-Process -FilePath $exePath -PassThru -RedirectStandardError $stderrFile -NoNewWindow

Start-Sleep -Seconds 15

if (!$proc.HasExited) {
    Write-Host "Game still running after 15 seconds, stopping..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    $proc.WaitForExit()
    Write-Host "Game stopped normally (no crash)" -ForegroundColor Green
} else {
    Write-Host "Game exited/crashed" -ForegroundColor Red
    Write-Host "Exit code: $($proc.ExitCode)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Crash trace output (last 150 lines):" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

if (Test-Path $stderrFile) {
    Get-Content $stderrFile | Select-Object -Last 150
} else {
    Write-Host "No trace file found" -ForegroundColor Red
}

