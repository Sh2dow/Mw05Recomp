# Test script to capture thread creation in MW05
# This script runs the game for 15 seconds and captures all thread creation messages

# Kill any existing instances
taskkill /F /IM Mw05Recomp.exe 2>&1 | Out-Null

# Set environment variables
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_HOSTOPS = "1"

# Change to build directory
Set-Location "out/build/x64-Clang-Debug/Mw05Recomp"

# Remove old trace log
Remove-Item -ErrorAction SilentlyContinue mw05_host_trace.log

Write-Host "Starting MW05 with kernel tracing enabled..."
Write-Host "Will run for 15 seconds and capture thread creation..."

# Start the game in background
$process = Start-Process -FilePath ".\Mw05Recomp.exe" -PassThru -RedirectStandardError "stderr.txt" -NoNewWindow

# Wait 20 seconds to see if more threads are created
Start-Sleep -Seconds 20

# Kill the process
Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue

Write-Host "`nGame stopped. Analyzing results..."

# Check if trace log exists
if (Test-Path "mw05_host_trace.log") {
    Write-Host "`n=== THREAD CREATION LOG ==="
    Get-Content "mw05_host_trace.log" | Select-String "ExCreateThread" | Select-Object -First 50
    
    Write-Host "`n=== FILE I/O LOG ==="
    Get-Content "mw05_host_trace.log" | Select-String "NtCreateFile|NtOpenFile" | Select-Object -First 30
} else {
    Write-Host "ERROR: Trace log not found!"
}

# Check stderr for thread creation messages
if (Test-Path "stderr.txt") {
    Write-Host "`n=== STDERR THREAD CREATION ==="
    Get-Content "stderr.txt" | Select-String "MW05_FIX.*Thread" | Select-Object -First 50
}

Write-Host "`nDone!"

