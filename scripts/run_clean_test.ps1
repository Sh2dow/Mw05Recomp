# Debug script - test current state of draws
param([int]$Seconds = 15)

$ErrorActionPreference = "Stop"

# Ensure Traces directory exists
New-Item -ItemType Directory -Path "Traces" -Force | Out-Null

# Clean old logs
Remove-Item "Traces/test_*.txt" -ErrorAction SilentlyContinue
Remove-Item "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log" -ErrorAction SilentlyContinue

Write-Host "=== TESTING CURRENT STATE ===" -ForegroundColor Cyan
Write-Host "Running game for $Seconds seconds..." -ForegroundColor Green

# Minimal settings - let game run naturally
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

cd out/build/x64-Clang-Debug/Mw05Recomp

$proc = Start-Process -FilePath "./Mw05Recomp.exe" -PassThru -NoNewWindow -RedirectStandardError "../../../../Traces/test_stderr.txt"
Write-Host "Game started (PID: $($proc.Id))"

Start-Sleep -Seconds $Seconds

if (-not $proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
} else {
    Write-Host "Game exited early (code: $($proc.ExitCode))" -ForegroundColor Red
}

# Copy trace log to Traces
if (Test-Path "mw05_host_trace.log") {
    Copy-Item "mw05_host_trace.log" "../../../../Traces/test_trace.log" -Force
}

cd ../../../..

Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

if (Test-Path "Traces/test_trace.log") {
    $isrCalls = (Get-Content "Traces/test_trace.log" | Select-String "guest_isr.call").Count
    $vdSwaps = (Get-Content "Traces/test_trace.log" | Select-String "HOST.VdSwap").Count
    $drawLines = Get-Content "Traces/test_trace.log" | Select-String "DrawCount"

    Write-Host "Guest ISR calls: $isrCalls"
    Write-Host "VdSwap calls: $vdSwaps"
    Write-Host "Draw command lines: $($drawLines.Count)"

    if ($drawLines.Count -gt 0) {
        $lastDraw = $drawLines | Select-Object -Last 1
        if ($lastDraw -match "DrawCount=(\d+)") {
            $drawCount = $matches[1]
            if ($drawCount -eq "0") {
                Write-Host "Draw count: $drawCount (NO DRAWS)" -ForegroundColor Red
            } else {
                Write-Host "Draw count: $drawCount" -ForegroundColor Green
            }
        }
    }

    if ($isrCalls -eq 0) {
        Write-Host "`nWARNING: Guest ISR not being called" -ForegroundColor Yellow
        $cbDisabled = Get-Content "Traces/test_trace.log" | Select-String "cb_on_init DISABLED"
        if ($cbDisabled) {
            Write-Host "  Reason: cb_on is DISABLED" -ForegroundColor Red
        }
    }
} else {
    Write-Host "No trace log found!" -ForegroundColor Red
}

Write-Host "`nLogs saved to Traces/ directory" -ForegroundColor Green

