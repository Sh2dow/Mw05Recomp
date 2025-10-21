$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Starting game WITHOUT stderr redirection..." -ForegroundColor Cyan
Write-Host "This will show if messageboxes appear when stderr is not redirected" -ForegroundColor Yellow

# Start WITHOUT redirecting stderr
$proc = Start-Process -FilePath $exePath -PassThru -NoNewWindow

# Load Windows Forms for sending keys
Add-Type -AssemblyName System.Windows.Forms

# Watch for 30 seconds
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    
    # Check if process is still running
    $running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $running) {
        Write-Host "`n[SECOND $i] Process exited" -ForegroundColor Yellow
        
        # Wait a bit to see if messagebox appears
        Start-Sleep -Seconds 3
        
        # Check for messageboxes
        $msgboxes = Get-Process | Where-Object { 
            $_.MainWindowTitle -like "*assertion*" -or 
            $_.MainWindowTitle -like "*Debug Error*" -or 
            $_.MainWindowTitle -like "*Runtime Library*" -or
            $_.MainWindowTitle -like "*Microsoft Visual C++*" -or
            $_.MainWindowTitle -like "*Mw05*"
        }
        
        if ($msgboxes) {
            Write-Host "`n!!! MESSAGEBOX FOUND !!!" -ForegroundColor Red
            $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List
            
            # Auto-click Ignore
            Write-Host "Auto-clicking Ignore..." -ForegroundColor Yellow
            $wshell = New-Object -ComObject WScript.Shell
            $wshell.AppActivate($msgboxes[0].Id)
            Start-Sleep -Milliseconds 300
            [System.Windows.Forms.SendKeys]::SendWait("I")
            Start-Sleep -Milliseconds 500
            
            # Kill it
            Stop-Process -Id $msgboxes[0].Id -Force -ErrorAction SilentlyContinue
            Write-Host "Messagebox dismissed" -ForegroundColor Green
        } else {
            Write-Host "No messagebox found" -ForegroundColor Green
        }
        
        break
    }
    
    # Check for messageboxes while running
    $msgboxes = Get-Process | Where-Object { 
        $_.MainWindowTitle -like "*assertion*" -or 
        $_.MainWindowTitle -like "*Debug Error*" -or 
        $_.MainWindowTitle -like "*Runtime Library*" -or
        $_.MainWindowTitle -like "*Microsoft Visual C++*" -or
        $_.MainWindowTitle -like "*Mw05*"
    }
    
    if ($msgboxes) {
        Write-Host "`n[SECOND $i] MESSAGEBOX DETECTED WHILE RUNNING!" -ForegroundColor Red
        $msgboxes | Select-Object ProcessName, MainWindowTitle, Id | Format-List
        
        # Auto-click Ignore
        Write-Host "Auto-clicking Ignore..." -ForegroundColor Yellow
        $wshell = New-Object -ComObject WScript.Shell
        $wshell.AppActivate($msgboxes[0].Id)
        Start-Sleep -Milliseconds 300
        [System.Windows.Forms.SendKeys]::SendWait("I")
        Start-Sleep -Milliseconds 500
    }
    
    if ($i % 5 -eq 0 -and $i -gt 0) {
        Write-Host "[SECOND $i] Still watching..." -ForegroundColor Green
    }
}

# Kill any remaining instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`nTest complete" -ForegroundColor Cyan

