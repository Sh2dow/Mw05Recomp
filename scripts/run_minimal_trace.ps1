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

# Enable ONLY host operations tracing (default ON, low volume)
# Disable imports tracing (high volume, causes heap issues)
$env:MW05_HOST_TRACE_HOSTOPS = "1"
$env:MW05_HOST_TRACE_IMPORTS = "0"  # Disable to avoid heap corruption
$env:MW05_TRACE_KERNEL = "0"        # Disable to avoid heap corruption
$env:MW05_PM4_TRACE = "0"            # Disable to avoid heap corruption

cd out/build/x64-Clang-Debug/Mw05Recomp
$proc = Start-Process -FilePath "./Mw05Recomp.exe" -PassThru -NoNewWindow -RedirectStandardError "../../../../Traces/minimal_stderr.txt"
Write-Host "Game started with PID: $($proc.Id)"

Start-Sleep -Seconds $Seconds

if (-not $proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

# Copy trace log to Traces directory
if (Test-Path "mw05_host_trace.log") {
    Copy-Item "mw05_host_trace.log" "../../../../Traces/minimal_trace.log" -Force
    Write-Host "Trace log copied to Traces/minimal_trace.log" -ForegroundColor Green
    
    # Show summary
    $lineCount = (Get-Content "../../../../Traces/minimal_trace.log" | Measure-Object -Line).Lines
    Write-Host "Trace log has $lineCount lines" -ForegroundColor Cyan
} else {
    Write-Host "No trace log generated" -ForegroundColor Red
}

cd ../../../..

Write-Host "`nDone. Logs in Traces/ directory" -ForegroundColor Green

