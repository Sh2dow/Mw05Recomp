#!/usr/bin/env pwsh
# Test script to enable MW05 micro-IB interpreter and dump system command buffer

$env:MW05_DUMP_SYSBUF = "1"
$env:MW05_FORCE_MICROIB = "1"
$env:MW05_PM4_FORCE_SYSBUF_SCAN = "1"

Write-Host "=== Testing MW05 Micro-IB Interpreter ===" -ForegroundColor Cyan
Write-Host "MW05_DUMP_SYSBUF=$env:MW05_DUMP_SYSBUF" -ForegroundColor Yellow
Write-Host "MW05_FORCE_MICROIB=$env:MW05_FORCE_MICROIB" -ForegroundColor Yellow
Write-Host "MW05_PM4_FORCE_SYSBUF_SCAN=$env:MW05_PM4_FORCE_SYSBUF_SCAN" -ForegroundColor Yellow
Write-Host ""

./run_with_debug.ps1

Write-Host ""
Write-Host "=== Checking for MicroIB traces ===" -ForegroundColor Cyan
if (Test-Path "traces") {
    Get-ChildItem -Path "traces" -Filter "*.bin" | ForEach-Object {
        Write-Host "Found: $($_.Name) ($($_.Length) bytes)" -ForegroundColor Green
    }
} else {
    Write-Host "No traces directory found" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Checking for MicroIB log messages ===" -ForegroundColor Cyan
if (Test-Path "debug_stderr.txt") {
    $microib_lines = Get-Content "debug_stderr.txt" | Select-String "MicroIB|MW05"
    if ($microib_lines) {
        Write-Host "Found $($microib_lines.Count) MicroIB log lines:" -ForegroundColor Green
        $microib_lines | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "No MicroIB log messages found in debug_stderr.txt" -ForegroundColor Red
    }
} else {
    Write-Host "No debug_stderr.txt found" -ForegroundColor Red
}

