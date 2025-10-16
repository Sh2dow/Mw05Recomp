#!/usr/bin/env pwsh
# Run game with PM4 tracing enabled

$env:MW05_PM4_TRACE = "1"
$env:MW05_FAST_BOOT = "1"

$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "Error: $exePath not found" -ForegroundColor Red
    exit 1
}

Write-Host "Running with PM4 tracing enabled..." -ForegroundColor Green
Write-Host "Environment variables:" -ForegroundColor Cyan
Write-Host "  MW05_PM4_TRACE=$($env:MW05_PM4_TRACE)"
Write-Host "  MW05_FAST_BOOT=$($env:MW05_FAST_BOOT)"
Write-Host ""

# Run for 5 seconds
$timeout = 5
$process = Start-Process -FilePath $exePath -NoNewWindow -PassThru

Start-Sleep -Seconds $timeout
Stop-Process -InputObject $process -Force -ErrorAction SilentlyContinue

Write-Host "Process stopped after $timeout seconds" -ForegroundColor Green

