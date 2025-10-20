# Test script to verify streaming bridge fix
# This enables the streaming bridge and file I/O logging to see if the game starts loading files

Write-Host "=== Testing Streaming Bridge Fix ===" -ForegroundColor Cyan
Write-Host "Enabling streaming bridge and file I/O logging..." -ForegroundColor Yellow

# Kill any running instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# TEST WITH MINIMAL FLAGS - Let game run naturally to see the crash
# Clear ALL environment variables to test natural game behavior

# Output directory
$LogDir = ".\out\build\x64-Clang-Debug\Mw05Recomp"
$stderrPath = "$LogDir\stderr_streaming_test.txt"
$stdoutPath = "$LogDir\stdout_streaming_test.txt"
$tracePath = "$LogDir\mw05_host_trace.log"

# Clear old logs
if (Test-Path $stderrPath) { Remove-Item $stderrPath -Force }
if (Test-Path $stdoutPath) { Remove-Item $stdoutPath -Force }
if (Test-Path $tracePath) { Remove-Item $tracePath -Force }

# Run the game
Write-Host "Starting game..." -ForegroundColor Green
$exePath = ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

if (!(Test-Path $exePath)) {
    Write-Host "ERROR: Executable not found at $exePath" -ForegroundColor Red
    exit 1
}

# Start process and capture output
$process = Start-Process -FilePath $exePath -WorkingDirectory ".\out\build\x64-Clang-Debug\Mw05Recomp" `
    -RedirectStandardError $stderrPath -RedirectStandardOutput $stdoutPath `
    -PassThru -WindowStyle Hidden

Write-Host "Game started with PID $($process.Id). Running for 60 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

# Kill the process
Write-Host "Stopping game..." -ForegroundColor Yellow
if (!$process.HasExited) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Analyze results
Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

# Check for file I/O
Write-Host "`n--- File I/O Activity ---" -ForegroundColor Yellow
if (Test-Path $tracePath) {
    $fileIOLines = Get-Content $tracePath -ErrorAction SilentlyContinue | Select-String "HOST.FileSystem|HOST.StreamBridge"
    if ($fileIOLines) {
        Write-Host "File I/O detected! ($($fileIOLines.Count) operations)" -ForegroundColor Green
        Write-Host "First 10 file operations:" -ForegroundColor Cyan
        $fileIOLines | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "NO file I/O detected" -ForegroundColor Red
    }
} else {
    Write-Host "Trace log not found" -ForegroundColor Red
}

# Check for streaming bridge activity
Write-Host "`n--- Streaming Bridge Activity ---" -ForegroundColor Yellow
if (Test-Path $tracePath) {
    $streamLines = Get-Content $tracePath -ErrorAction SilentlyContinue | Select-String "StreamBridge"
    if ($streamLines) {
        Write-Host "Streaming bridge active! ($($streamLines.Count) events)" -ForegroundColor Green
        Write-Host "First 10 streaming events:" -ForegroundColor Cyan
        $streamLines | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "NO streaming bridge activity" -ForegroundColor Red
    }
}

# Check for draws
Write-Host "`n--- Draw Commands ---" -ForegroundColor Yellow
if (Test-Path $stderrPath) {
    $drawLines = Get-Content $stderrPath -ErrorAction SilentlyContinue | Select-String "draws="
    if ($drawLines) {
        $lastDraw = $drawLines | Select-Object -Last 1
        Write-Host "Last draw count: $lastDraw" -ForegroundColor Cyan
        if ($lastDraw -match "draws=(\d+)") {
            $drawCount = [int]$matches[1]
            if ($drawCount -gt 0) {
                Write-Host "SUCCESS: Draws detected! ($drawCount draws)" -ForegroundColor Green
            } else {
                Write-Host "No draws yet (draws=0)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "No draw information found" -ForegroundColor Red
    }
}

# Check for crashes
Write-Host "`n--- Crash Detection ---" -ForegroundColor Yellow
if (Test-Path $stderrPath) {
    $crashLines = Get-Content $stderrPath -ErrorAction SilentlyContinue | Select-String "crash|exception|error" -CaseSensitive:$false
    if ($crashLines) {
        Write-Host "Potential crash detected! ($($crashLines.Count) error messages)" -ForegroundColor Red
        Write-Host "Last 5 error messages:" -ForegroundColor Cyan
        $crashLines | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "No crashes detected" -ForegroundColor Green
    }
}

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Logs saved to:" -ForegroundColor Yellow
Write-Host "  stderr: $stderrPath"
Write-Host "  stdout: $stdoutPath"
Write-Host "  trace:  $tracePath"

Write-Host "`nTest complete!" -ForegroundColor Green

