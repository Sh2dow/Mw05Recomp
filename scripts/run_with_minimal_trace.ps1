param(
    [int]$Seconds = 30
)

$ErrorActionPreference = "Stop"

# Ensure Traces directory exists
New-Item -ItemType Directory -Path "Traces" -Force | Out-Null

# Clean old logs
Remove-Item "Traces/minimal_*.txt" -ErrorAction SilentlyContinue
Remove-Item "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log" -ErrorAction SilentlyContinue

Write-Host "Starting game with MINIMAL tracing for $Seconds seconds..." -ForegroundColor Green
Write-Host "Only HOST operations will be traced (low volume)" -ForegroundColor Yellow

# Set environment variables in current process (will be inherited)
$env:MW05_HOST_TRACE_HOSTOPS = "1"
$env:MW05_HOST_TRACE_IMPORTS = "0"
$env:MW05_TRACE_KERNEL = "0"
$env:MW05_PM4_TRACE = "0"

# Run directly without Start-Process to inherit environment
cd out/build/x64-Clang-Debug/Mw05Recomp

Write-Host "Starting game..." -ForegroundColor Cyan

# Start game in background job to allow timeout
$job = Start-Job -ScriptBlock {
    param($exePath)
    & $exePath 2>&1
} -ArgumentList (Resolve-Path "./Mw05Recomp.exe").Path

Write-Host "Game started as background job"

# Wait for specified time
Start-Sleep -Seconds $Seconds

# Stop the job
Write-Host "Stopping game..." -ForegroundColor Yellow
Stop-Job -Job $job -ErrorAction SilentlyContinue
Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

# Also kill any remaining processes
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

Start-Sleep -Seconds 2

# Copy trace log to Traces directory
if (Test-Path "mw05_host_trace.log") {
    Copy-Item "mw05_host_trace.log" "../../../../Traces/minimal_trace.log" -Force
    Write-Host "Trace log copied to Traces/minimal_trace.log" -ForegroundColor Green
    
    # Show summary
    $lineCount = (Get-Content "../../../../Traces/minimal_trace.log" | Measure-Object -Line).Lines
    Write-Host "Trace log has $lineCount lines" -ForegroundColor Cyan
    
    # Show first few lines
    Write-Host "`nFirst 10 lines:" -ForegroundColor Cyan
    Get-Content "../../../../Traces/minimal_trace.log" | Select-Object -First 10
} else {
    Write-Host "No trace log generated" -ForegroundColor Red
}

cd ../../../..

Write-Host "`nDone. Logs in Traces/ directory" -ForegroundColor Green

