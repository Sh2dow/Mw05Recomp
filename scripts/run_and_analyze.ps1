param(
    [int]$Seconds = 30
)

$ErrorActionPreference = "Stop"

# Ensure Traces directory exists
New-Item -ItemType Directory -Path "Traces" -Force | Out-Null

# Clean old logs
Remove-Item "Traces/run_*.txt" -ErrorAction SilentlyContinue
Remove-Item "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log" -ErrorAction SilentlyContinue

Write-Host "Starting game for $Seconds seconds..." -ForegroundColor Green

# Enable debug profile for tracing
$env:MW05_DEBUG_PROFILE = "1"

cd out/build/x64-Clang-Debug/Mw05Recomp
$proc = Start-Process -FilePath "./Mw05Recomp.exe" -ArgumentList "--mwdebug" -PassThru -NoNewWindow -RedirectStandardError "../../../../Traces/run_stderr.txt"
Write-Host "Game started with PID: $($proc.Id)"

Start-Sleep -Seconds $Seconds

if (-not $proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

# Copy trace log to Traces directory
if (Test-Path "mw05_host_trace.log") {
    Copy-Item "mw05_host_trace.log" "../../../../Traces/mw05_host_trace.log" -Force
    Write-Host "Trace log copied to Traces/mw05_host_trace.log" -ForegroundColor Green
}

cd ../../../..

Write-Host "`nAnalyzing results..." -ForegroundColor Cyan

# Count VdSwap calls
$vdswapCount = (Get-Content "Traces/mw05_host_trace.log" -ErrorAction SilentlyContinue | Select-String "VdSwap" | Measure-Object).Count
Write-Host "VdSwap calls: $vdswapCount"

# Count PM4 packets
$pm4Line = Get-Content "Traces/mw05_host_trace.log" -ErrorAction SilentlyContinue | Select-String "PM4.ScanAllOnPresent" | Select-Object -Last 1
if ($pm4Line) {
    if ($pm4Line -match "pkts=(\d+)") {
        Write-Host "PM4 packets processed: $($matches[1])"
    }
    if ($pm4Line -match "draws=(\d+)") {
        $draws = $matches[1]
        if ($draws -eq "0") {
            Write-Host "Draw commands: $draws (NONE YET)" -ForegroundColor Red
        } else {
            Write-Host "Draw commands: $draws" -ForegroundColor Green
        }
    }
}

# Check for errors
$errors = Get-Content "Traces/run_stderr.txt" -ErrorAction SilentlyContinue | Select-String "ERROR|CRASH|exception"
if ($errors) {
    Write-Host "`nErrors found:" -ForegroundColor Red
    $errors | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`nDone. Logs in Traces/ directory" -ForegroundColor Green

