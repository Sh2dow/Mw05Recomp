$env:MW05_XEX_PATH = "D:/Games/Xbox360/NFS Most Wanted/default.xex"
$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$logPath = "D:/Repos/Games/Mw05Recomp/traces/click_ignore.txt"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Starting game and watching for messageboxes..." -ForegroundColor Cyan
$proc = Start-Process -FilePath $exePath -RedirectStandardError $logPath -PassThru -NoNewWindow

# Load Windows Forms for sending keys
Add-Type -AssemblyName System.Windows.Forms

# Watch for 60 seconds
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 1
    
    # Check if process is still running
    $running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $running) {
        Write-Host "`n[SECOND $i] Process exited" -ForegroundColor Yellow
        
        # Wait a bit more to see if messagebox appears after process exit
        Start-Sleep -Seconds 2
        
        # Check for messageboxes one more time
        $msgboxes = Get-Process | Where-Object { 
            $_.MainWindowTitle -like "*assertion*" -or 
            $_.MainWindowTitle -like "*Debug Error*" -or 
            $_.MainWindowTitle -like "*Runtime Library*" -or
            $_.MainWindowTitle -like "*Microsoft Visual C++*"
        }
        
        if ($msgboxes) {
            Write-Host "`n!!! MESSAGEBOX FOUND AFTER PROCESS EXIT !!!" -ForegroundColor Red
            $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List
            
            # Click Ignore button
            Write-Host "Clicking Ignore button..." -ForegroundColor Yellow
            $wshell = New-Object -ComObject WScript.Shell
            $wshell.AppActivate($msgboxes[0].Id)
            Start-Sleep -Milliseconds 200
            [System.Windows.Forms.SendKeys]::SendWait("I")
            Start-Sleep -Milliseconds 500
            
            # Kill the messagebox process
            Stop-Process -Id $msgboxes[0].Id -Force -ErrorAction SilentlyContinue
        }
        
        break
    }
    
    # Check for messageboxes while running
    $msgboxes = Get-Process | Where-Object { 
        $_.MainWindowTitle -like "*assertion*" -or 
        $_.MainWindowTitle -like "*Debug Error*" -or 
        $_.MainWindowTitle -like "*Runtime Library*" -or
        $_.MainWindowTitle -like "*Microsoft Visual C++*"
    }
    
    if ($msgboxes) {
        Write-Host "`n[SECOND $i] MESSAGEBOX DETECTED!" -ForegroundColor Red
        $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List
        
        # Show assertion text from log
        if (Test-Path $logPath) {
            Write-Host "`nAssertion details:" -ForegroundColor Yellow
            Get-Content $logPath | Select-String "Assertion|assertion|assert" | Select-Object -Last 5
        }
        
        # Click Ignore button
        Write-Host "Clicking Ignore button..." -ForegroundColor Yellow
        $wshell = New-Object -ComObject WScript.Shell
        $wshell.AppActivate($msgboxes[0].Id)
        Start-Sleep -Milliseconds 200
        [System.Windows.Forms.SendKeys]::SendWait("I")
        Start-Sleep -Milliseconds 500
    }
    
    if ($i % 10 -eq 0 -and $i -gt 0) {
        Write-Host "[SECOND $i] Still watching..." -ForegroundColor Green
    }
}

# Kill any remaining instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n=== LOG CONTENT ===" -ForegroundColor Cyan
if (Test-Path $logPath) {
    $content = Get-Content $logPath
    
    # Check for assertions
    $assertions = $content | Select-String "assert|ASSERT|Assertion"
    if ($assertions) {
        Write-Host "`nAssertions found:" -ForegroundColor Yellow
        $assertions | Select-Object -Last 10
    } else {
        Write-Host "No assertions found in log" -ForegroundColor Green
    }
    
    # Show last few lines
    Write-Host "`nLast 30 lines:" -ForegroundColor Yellow
    $content | Select-Object -Last 30
} else {
    Write-Host "Log file not found: $logPath" -ForegroundColor Red
}

