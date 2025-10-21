# Monitor game progress during long run
param(
    [int]$WaitMinutes = 2
)

Write-Host "Waiting $WaitMinutes minutes..."
Start-Sleep -Seconds ($WaitMinutes * 60)

Write-Host "`n=== PROGRESS CHECK ==="
$consoleLog = "out\build\x64-Clang-Debug\Mw05Recomp\mw05_console_out.log"
$traceLog = "out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log"

if (Test-Path $consoleLog) {
    # Check for draws
    $drawsLine = Get-Content $consoleLog | Select-String 'PM4.*draws=' | Select-Object -Last 1
    if ($drawsLine) {
        Write-Host "Latest PM4 scan: $drawsLine"
    } else {
        Write-Host "No PM4 scan messages found"
    }
    
    # Check for FILE-OPEN messages
    $fileOpenCount = (Get-Content $consoleLog | Select-String 'FILE-OPEN').Count
    Write-Host "FILE-OPEN messages: $fileOpenCount"
    
    # Check for FPS
    $fpsLine = Get-Content $consoleLog | Select-String 'FPS=' | Select-Object -Last 1
    if ($fpsLine) {
        Write-Host "Latest FPS: $fpsLine"
    }
} else {
    Write-Host "Console log not found at $consoleLog"
}

if (Test-Path $traceLog) {
    # Count StreamBridge operations
    $streamCount = (Get-Content $traceLog | Select-String 'StreamBridge').Count
    Write-Host "StreamBridge operations: $streamCount"
    
    # Count file I/O operations
    $fileIOCount = (Get-Content $traceLog | Select-String 'NtCreateFile|NtOpenFile|NtReadFile').Count
    Write-Host "File I/O operations: $fileIOCount"
} else {
    Write-Host "Trace log not found at $traceLog"
}

Write-Host "=== END PROGRESS CHECK ===`n"

