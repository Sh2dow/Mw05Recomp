# Test script to capture ALL messageboxes

Write-Host "Starting game WITHOUT stderr redirection to see messageboxes..." -ForegroundColor Cyan

# Start the game process WITHOUT redirecting stderr
$process = Start-Process -FilePath "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -WorkingDirectory "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp"

# Monitor for messageboxes
for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 1
    
    # Check if process exited
    if ($process.HasExited) {
        Write-Host "`n[SECOND $i] Process exited with code $($process.ExitCode)" -ForegroundColor Yellow
        break
    }
    
    # Look for ANY windows with common messagebox titles
    $msgboxes = Get-Process | Where-Object { 
        $_.MainWindowTitle -match "Mw05|Microsoft|Runtime|Debug|Error|assert|Assertion|Failed|abort" -and
        $_.Id -ne $process.Id
    }
    
    if ($msgboxes) {
        Write-Host "`n[SECOND $i] MESSAGEBOX DETECTED!" -ForegroundColor Red
        $msgboxes | ForEach-Object {
            Write-Host "  Process: $($_.ProcessName)" -ForegroundColor Red
            Write-Host "  Title: $($_.MainWindowTitle)" -ForegroundColor Red
            Write-Host "  PID: $($_.Id)" -ForegroundColor Red
            Write-Host ""
        }
        
        # Try to read the messagebox text using UI Automation
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        
        try {
            $automation = [System.Windows.Automation.AutomationElement]::RootElement
            $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $msgboxes[0].Id)
            $window = $automation.FindFirst([System.Windows.Automation.TreeScope]::Children, $condition)
            
            if ($window) {
                $textCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
                $textElements = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $textCondition)
                
                Write-Host "Messagebox text:" -ForegroundColor Yellow
                foreach ($element in $textElements) {
                    $text = $element.Current.Name
                    if ($text -and $text.Trim() -ne "") {
                        Write-Host "  $text" -ForegroundColor Yellow
                    }
                }
            }
        } catch {
            Write-Host "Could not read messagebox text: $_" -ForegroundColor Gray
        }
        
        # Auto-click Ignore button
        Write-Host "Attempting to auto-click Ignore..." -ForegroundColor Cyan
        $wshell = New-Object -ComObject WScript.Shell
        $activated = $wshell.AppActivate($msgboxes[0].Id)
        if ($activated) {
            Start-Sleep -Milliseconds 500
            $wshell.SendKeys("I")  # Press 'I' for Ignore
            Write-Host "Sent 'I' key" -ForegroundColor Green
        } else {
            Write-Host "Failed to activate window" -ForegroundColor Red
        }
    }
    
    if ($i % 10 -eq 0) {
        Write-Host "[SECOND $i] Game still running..." -ForegroundColor Green
    }
}

# Kill process if still running
if (!$process.HasExited) {
    Write-Host "`nKilling process..." -ForegroundColor Yellow
    $process.Kill()
    $process.WaitForExit(5000)
}

Write-Host "`nTest complete" -ForegroundColor Cyan

