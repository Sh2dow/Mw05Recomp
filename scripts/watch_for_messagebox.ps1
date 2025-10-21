$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/messagebox_watch.txt"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Starting game..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow -RedirectStandardError $logPath

# Watch for 30 seconds
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    
    # Check if process is still running
    $running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    
    if (-not $running) {
        Write-Host "`n[SECOND $i] PROCESS EXITED!" -ForegroundColor Red
        break
    }
    
    # Check for messageboxes
    $msgboxes = Get-Process | Where-Object { 
        $_.MainWindowTitle -like "*Mw05*" -or 
        $_.MainWindowTitle -like "*Debug Error*" -or 
        $_.MainWindowTitle -like "*Runtime Library*" -or
        $_.MainWindowTitle -like "*Failed*"
    }
    
    if ($msgboxes) {
        Write-Host "`n[SECOND $i] MESSAGEBOX DETECTED!" -ForegroundColor Red
        $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List
        
        # Kill the process
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        break
    }
    
    if ($i % 5 -eq 0) {
        Write-Host "[SECOND $i] Game still running, no messageboxes" -ForegroundColor Green
    }
}

# Clean up
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n=== LOG CONTENT ===" -ForegroundColor Cyan
if (Test-Path $logPath) {
    $content = Get-Content $logPath
    
    # Check for errors
    $errors = $content | Select-String "error|ERROR|Failed|FAILED|assert|ASSERT|crash|CRASH"
    if ($errors) {
        Write-Host "`nErrors found:" -ForegroundColor Yellow
        $errors | Select-Object -Last 20
    } else {
        Write-Host "No errors found" -ForegroundColor Green
    }
    
    # Show last few lines
    Write-Host "`nLast 30 lines:" -ForegroundColor Yellow
    $content | Select-Object -Last 30
} else {
    Write-Host "Log file not found: $logPath" -ForegroundColor Red
}

