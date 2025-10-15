param(
    [int]$Seconds = 30
)

$ErrorActionPreference = "Stop"

# Ensure Traces directory exists
New-Item -ItemType Directory -Path "Traces" -Force | Out-Null

# Clean old logs
Remove-Item "Traces/file_trace_*.txt" -ErrorAction SilentlyContinue
Remove-Item "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log" -ErrorAction SilentlyContinue

Write-Host "Starting game with FILE I/O tracing for $Seconds seconds..." -ForegroundColor Green
Write-Host "Environment variables:" -ForegroundColor Yellow
Write-Host "  MW05_FILE_LOG=1" -ForegroundColor Cyan
Write-Host "  MW05_HOST_TRACE_HOSTOPS=1" -ForegroundColor Cyan

# Set environment variables
$env:MW05_FILE_LOG = "1"
$env:MW05_HOST_TRACE_HOSTOPS = "1"
$env:MW05_HOST_TRACE_IMPORTS = "0"
$env:MW05_TRACE_KERNEL = "0"
$env:MW05_PM4_TRACE = "0"

cd out/build/x64-Clang-Debug/Mw05Recomp

# Start game
$proc = Start-Process -FilePath "./Mw05Recomp.exe" -PassThru -NoNewWindow -RedirectStandardError "../../../../Traces/file_trace_stderr.txt"
Write-Host "Game started with PID: $($proc.Id)" -ForegroundColor Green

Start-Sleep -Seconds $Seconds

if (-not $proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

# Copy trace log to Traces directory
if (Test-Path "mw05_host_trace.log") {
    Copy-Item "mw05_host_trace.log" "../../../../Traces/file_trace.log" -Force
    Write-Host "Trace log copied to Traces/file_trace.log" -ForegroundColor Green
    
    # Show summary
    $content = Get-Content "../../../../Traces/file_trace.log"
    $lineCount = $content.Count
    Write-Host "`nTrace log has $lineCount lines" -ForegroundColor Cyan
    
    # Count file operations
    $fileOps = $content | Select-String -Pattern "FileSystem" | Measure-Object
    Write-Host "File operations: $($fileOps.Count)" -ForegroundColor Cyan
    
    # Show first 20 file operations
    if ($fileOps.Count -gt 0) {
        Write-Host "`nFirst 20 file operations:" -ForegroundColor Yellow
        $content | Select-String -Pattern "FileSystem" | Select-Object -First 20
    } else {
        Write-Host "`nNO FILE OPERATIONS DETECTED!" -ForegroundColor Red
    }
} else {
    Write-Host "No trace log generated" -ForegroundColor Red
}

cd ../../../..

Write-Host "`nDone. Logs in Traces/ directory" -ForegroundColor Green

