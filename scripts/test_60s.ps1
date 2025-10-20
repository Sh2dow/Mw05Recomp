$env:MW05_XEX_PATH = "D:/Games/Xbox360/NFS Most Wanted/default.xex"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/test_60s.txt"
$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Run for 180 seconds (3 minutes) and capture stderr
$duration = 180
Write-Host "Starting game for $duration seconds..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -RedirectStandardError $logPath -PassThru -NoNewWindow

# Monitor for messageboxes and auto-dismiss them
$messageboxDetected = $false
for ($i = 0; $i -lt $duration; $i++) {
    Start-Sleep -Seconds 1

    # Check if process is still running
    $running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $running) {
        Write-Host "`n[SECOND $i] Process exited!" -ForegroundColor Red
        break
    }

    # Check for messageboxes
    $msgboxes = Get-Process | Where-Object {
        $_.MainWindowTitle -like "*assertion*" -or
        $_.MainWindowTitle -like "*Debug Error*" -or
        $_.MainWindowTitle -like "*Runtime Library*" -or
        $_.MainWindowTitle -like "*Failed*" -or
        $_.MainWindowTitle -like "*Mw05 Recompiled*"
    } | Where-Object { $_.Id -ne $proc.Id }  # Exclude the main game window

    if ($msgboxes -and -not $messageboxDetected) {
        $messageboxDetected = $true
        Write-Host "`n[SECOND $i] MESSAGEBOX DETECTED!" -ForegroundColor Red
        $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List

        # Capture the assertion text from stderr log
        if (Test-Path $logPath) {
            Write-Host "`nAssertion details:" -ForegroundColor Yellow
            Get-Content $logPath | Select-String "Assertion|assertion|assert" | Select-Object -Last 5
        }

        # Try to auto-dismiss
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.SendKeys]::SendWait("I")  # Press 'I' for Ignore
        Start-Sleep -Milliseconds 200
    }

    if ($i % 30 -eq 0 -and $i -gt 0) {
        Write-Host "[SECOND $i] Game still running..." -ForegroundColor Green
    }
}

# Kill any remaining instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Show summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan

if ($messageboxDetected) {
    Write-Host "`n!!! MESSAGEBOX WAS DETECTED !!!" -ForegroundColor Red
}

Write-Host "`nHeap initialization:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "HEAP-INIT" | Select-Object -First 10

Write-Host "`nNULL-CALL errors:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "NULL-CALL" | Select-Object -First 10

Write-Host "`nThread creation:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "Thread #|FORCE_WORKERS" | Select-Object -First 20

Write-Host "`nPM4 stats:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "PM4-TYPE-DIST|draws=" | Select-Object -Last 5

Write-Host "`nFile I/O:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "XReadFile|XCreateFile|STREAM" | Select-Object -Last 10

Write-Host "`nCrashes/Assertions:" -ForegroundColor Yellow
Get-Content $logPath | Select-String "crash|CRASH|assert|ASSERT|exception|EXCEPTION" | Select-Object -Last 10

Write-Host "`nFull log saved to: $logPath" -ForegroundColor Green

