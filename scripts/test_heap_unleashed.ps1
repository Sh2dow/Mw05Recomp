param(
    [int]$TimeoutSeconds = 30
)

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Start the game
$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$process = Start-Process -FilePath $exePath -PassThru -RedirectStandardError "heap_test_stderr.txt" -NoNewWindow

Write-Host "[TEST] Started Mw05Recomp.exe (PID: $($process.Id))"
Write-Host "[TEST] Running for $TimeoutSeconds seconds..."

# Monitor for assertion dialogs and dismiss them
$startTime = Get-Date
$dialogDismissed = $false
$assertionFound = $false

while ((Get-Date) -lt $startTime.AddSeconds($TimeoutSeconds)) {
    # Check if process is still running
    if ($process.HasExited) {
        Write-Host "[TEST] Process exited with code: $($process.ExitCode)"
        break
    }

    # Look for assertion dialog by window title
    $windows = Get-Process | Where-Object { $_.MainWindowTitle -ne "" }
    foreach ($win in $windows) {
        if ($win.MainWindowTitle -match "Assertion|Debug|Error|Microsoft Visual C\+\+") {
            Write-Host "[TEST] Found dialog: '$($win.MainWindowTitle)' (PID: $($win.Id))"
            $assertionFound = $true

            # Try to close it
            Add-Type -AssemblyName System.Windows.Forms
            $wshell = New-Object -ComObject WScript.Shell
            $wshell.AppActivate($win.Id)
            Start-Sleep -Milliseconds 300

            # Try different keys to dismiss
            [System.Windows.Forms.SendKeys]::SendWait("A")  # Abort
            Start-Sleep -Milliseconds 200
            [System.Windows.Forms.SendKeys]::SendWait("{ESC}")  # Escape
            Start-Sleep -Milliseconds 200
            [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")  # Enter

            $dialogDismissed = $true
            Write-Host "[TEST] Attempted to dismiss dialog"
            Start-Sleep -Seconds 1
            break
        }
    }

    if ($dialogDismissed) {
        break
    }

    Start-Sleep -Milliseconds 100
}

# Kill process if still running
if (!$process.HasExited) {
    Write-Host "[TEST] Timeout reached, killing process..."
    $process.Kill()
    $process.WaitForExit(5000)
}

Write-Host "[TEST] Test complete"
if ($assertionFound) {
    Write-Host "[TEST] ASSERTION DETECTED!"
}
Write-Host ""
Write-Host "=== STDERR OUTPUT (last 80 lines) ==="
if (Test-Path "heap_test_stderr.txt") {
    Get-Content "heap_test_stderr.txt" | Select-Object -Last 80
} else {
    Write-Host "(no stderr output)"
}

