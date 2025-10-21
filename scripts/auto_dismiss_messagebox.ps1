$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/auto_dismiss.txt"

# Enable file I/O and streaming bridge logging
$env:MW05_FILE_LOG = "1"
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_STREAM_FALLBACK_BOOT = "1"
$env:MW05_HOST_TRACE_HOSTOPS = "1"

# Disable video thread creation to test if crash is related
# The crash is happening at second 5, before tick 300
$env:MW05_FORCE_VIDEO_THREAD = "0"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "300"
$env:MW05_FORCE_VIDEO_WORK_FLAG = "1"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Starting game..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow -RedirectStandardError $logPath

# Auto-dismiss messageboxes for 120 seconds (2 minutes) to see if game progresses
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Seconds 1
    
    # Check if process is still running
    $running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    
    if (-not $running) {
        Write-Host "`n[SECOND $i] PROCESS EXITED!" -ForegroundColor Red
        break
    }
    
    # Find and dismiss messageboxes - check for BOTH types
    $msgboxes = Get-Process | Where-Object {
        $_.MainWindowTitle -like "*assertion*" -or
        $_.MainWindowTitle -like "*Debug Error*" -or
        $_.MainWindowTitle -like "*Runtime Library*" -or
        $_.MainWindowTitle -like "*Failed*" -or
        $_.MainWindowTitle -like "*Mw05 Recompiled*" -or
        $_.MainWindowTitle -like "*abort*"
    }

    if ($msgboxes) {
        foreach ($msgbox in $msgboxes) {
            $title = $msgbox.MainWindowTitle
            Write-Host "[SECOND $i] Messagebox detected: '$title'" -ForegroundColor Yellow

            Add-Type -AssemblyName System.Windows.Forms
            $wshell = New-Object -ComObject WScript.Shell
            $wshell.AppActivate($msgbox.Id)
            Start-Sleep -Milliseconds 200

            # Handle different messagebox types
            if ($title -like "*Mw05 Recompiled*" -or $title -like "*Failed*") {
                # "Failed to locate guest entry point" - has OK button
                Write-Host "  -> Clicking OK button (Enter key)" -ForegroundColor Cyan
                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
            }
            elseif ($title -like "*Runtime Library*" -or $title -like "*abort*" -or $title -like "*Debug Error*") {
                # "abort() has been called" - has Abort/Retry/Ignore buttons
                Write-Host "  -> Clicking Ignore button (I key)" -ForegroundColor Cyan
                [System.Windows.Forms.SendKeys]::SendWait("I")
            }
            else {
                # Unknown messagebox - try both
                Write-Host "  -> Trying Escape, then Ignore, then OK" -ForegroundColor Cyan
                [System.Windows.Forms.SendKeys]::SendWait("{ESC}")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait("I")
                Start-Sleep -Milliseconds 100
                [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
            }

            Start-Sleep -Milliseconds 200
        }
    }
    
    if ($i % 10 -eq 0) {
        Write-Host "[SECOND $i] Game still running" -ForegroundColor Green
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

