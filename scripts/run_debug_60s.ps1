# Run game for 60 seconds and capture crash dump
$env:MW05_XEX_PATH = "D:/Games/Xbox360/NFS Most Wanted/default.xex"

$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/crash_debug.txt"

Write-Host "Starting game..." -ForegroundColor Green
Write-Host "Log file: $logPath" -ForegroundColor Cyan

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

# Start the process and redirect stderr to log file
$process = Start-Process -FilePath $exePath -RedirectStandardError $logPath -PassThru -NoNewWindow

# Wait for 60 seconds or until process exits
$timeout = 60
$elapsed = 0
while (-not $process.HasExited -and $elapsed -lt $timeout) {
    Start-Sleep -Seconds 1
    $elapsed++
    if ($elapsed % 5 -eq 0) {
        Write-Host "Running... $elapsed seconds" -ForegroundColor Yellow
    }
}

if ($process.HasExited) {
    Write-Host "`nProcess exited after $elapsed seconds with code: $($process.ExitCode)" -ForegroundColor Red
} else {
    Write-Host "`nTimeout reached ($timeout seconds), stopping process..." -ForegroundColor Yellow
    $process.Kill()
    $process.WaitForExit()
}

Write-Host "`nLast 100 lines of log:" -ForegroundColor Green
Get-Content $logPath | Select-Object -Last 100

Write-Host "`nSearching for CRITICAL errors:" -ForegroundColor Red
Get-Content $logPath | Select-String "CRITICAL" | Select-Object -Last 20

