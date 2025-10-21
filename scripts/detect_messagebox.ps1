$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/messagebox_test.txt"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Start the process
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow -RedirectStandardError $logPath

# Wait 5 seconds
Start-Sleep -Seconds 15

# Check if process is still running
$running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue

if ($running) {
    Write-Host "`n=== PROCESS STILL RUNNING ===" -ForegroundColor Red
    Write-Host "Process ID: $($running.Id)"
    Write-Host "Responding: $($running.Responding)"
    Write-Host "Main Window Title: '$($running.MainWindowTitle)'"
    
    # Check for assertion dialog
    $windows = Get-Process | Where-Object { $_.MainWindowTitle -like "*assertion*" -or $_.MainWindowTitle -like "*Debug Error*" -or $_.MainWindowTitle -like "*Runtime Library*" }
    if ($windows) {
        Write-Host "`n=== ASSERTION DIALOG DETECTED ===" -ForegroundColor Red
        $windows | Select-Object ProcessName, MainWindowTitle | Format-List
    }
    
    # Kill the process
    Stop-Process -Id $proc.Id -Force
} else {
    Write-Host "`n=== PROCESS EXITED CLEANLY ===" -ForegroundColor Green
}

# Show log content
Write-Host "`n=== LOG CONTENT ===" -ForegroundColor Cyan
if (Test-Path $logPath) {
    $content = Get-Content $logPath
    
    # Check for assertions
    $assertions = $content | Select-String "assert|ASSERT|Assertion|o1heap"
    if ($assertions) {
        Write-Host "`nAssertions found:" -ForegroundColor Yellow
        $assertions | Select-Object -Last 10
    } else {
        Write-Host "No assertions found" -ForegroundColor Green
    }
    
    # Show last few lines
    Write-Host "`nLast 20 lines:" -ForegroundColor Yellow
    $content | Select-Object -Last 20
} else {
    Write-Host "Log file not found: $logPath" -ForegroundColor Red
}

