#!/usr/bin/env pwsh
# Run MW05 with PM4 packet tracing enabled

$env:MW05_PM4_TRACE = "1"
$env:MW05_TRACE_KERNEL = "1"

Write-Host "Starting MW05 with PM4 packet tracing..." -ForegroundColor Green
Write-Host "Log file: .\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -ForegroundColor Cyan
Write-Host "Will run for 60 seconds..." -ForegroundColor Yellow
Write-Host ""

# Start the game
$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru

# Wait for 60 seconds
Start-Sleep -Seconds 60

# Kill the process
if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host "Done. Checking logs..." -ForegroundColor Green
Write-Host ""

# Check for PM4 traces
$pm4Lines = Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "HOST.PM4" | Select-Object -Last 20
if ($pm4Lines) {
    Write-Host "Found PM4 traces:" -ForegroundColor Green
    $pm4Lines | ForEach-Object { Write-Host $_.Line }
} else {
    Write-Host "No PM4 traces found" -ForegroundColor Red
    Write-Host "Checking for VdSwap traces..." -ForegroundColor Yellow
    $vdswapLines = Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "HOST.VdSwap" | Select-Object -Last 10
    if ($vdswapLines) {
        Write-Host "Found VdSwap traces:" -ForegroundColor Green
        $vdswapLines | ForEach-Object { Write-Host $_.Line }
    } else {
        Write-Host "No VdSwap traces found either" -ForegroundColor Red
    }
}

