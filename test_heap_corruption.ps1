# Test script to detect heap corruption and handle assertion dialogs
# This script runs the game and automatically dismisses assertion dialogs

param(
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Continue"

# Kill any existing instances
Write-Host "[TEST] Killing existing Mw05Recomp.exe processes..." -ForegroundColor Yellow
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Build the app first
Write-Host "[TEST] Building application..." -ForegroundColor Cyan
& ./build_cmd.ps1 -Stage app 2>&1 | Select-String 'error|App built' | ForEach-Object { Write-Host $_ }

if ($LASTEXITCODE -ne 0) {
    Write-Host "[TEST] Build FAILED!" -ForegroundColor Red
    exit 1
}

Write-Host "[TEST] Build succeeded!" -ForegroundColor Green

# Prepare output files
$outputFile = "heap_corruption_test.txt"
$stderrFile = "heap_corruption_stderr.txt"

# Start the game process
Write-Host "[TEST] Starting Mw05Recomp.exe..." -ForegroundColor Cyan
$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = $exePath
$processInfo.RedirectStandardError = $true
$processInfo.RedirectStandardOutput = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $false
$processInfo.WorkingDirectory = (Get-Location).Path

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo

# Event handlers for output
$stdoutBuilder = New-Object System.Text.StringBuilder
$stderrBuilder = New-Object System.Text.StringBuilder

$stdoutEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
    if ($EventArgs.Data) {
        [void]$Event.MessageData.AppendLine($EventArgs.Data)
        Write-Host $EventArgs.Data
    }
} -MessageData $stdoutBuilder

$stderrEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
    if ($EventArgs.Data) {
        [void]$Event.MessageData.AppendLine($EventArgs.Data)
        Write-Host $EventArgs.Data -ForegroundColor Yellow
    }
} -MessageData $stderrBuilder

# Start the process
[void]$process.Start()
$process.BeginOutputReadLine()
$process.BeginErrorReadLine()

Write-Host "[TEST] Process started (PID: $($process.Id))" -ForegroundColor Green
Write-Host "[TEST] Monitoring for $TimeoutSeconds seconds..." -ForegroundColor Cyan

# Monitor for assertion dialogs and heap corruption messages
$startTime = Get-Date
$foundCorruption = $false
$foundAssertion = $false

while (((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
    # Check if process has exited
    if ($process.HasExited) {
        Write-Host "[TEST] Process exited with code: $($process.ExitCode)" -ForegroundColor Yellow
        break
    }

    # Check for assertion dialog windows
    $assertionWindows = Get-Process | Where-Object { 
        $_.MainWindowTitle -match "Assertion|Debug|Error" -and 
        $_.ProcessName -ne "powershell"
    }

    if ($assertionWindows) {
        Write-Host "[TEST] Found assertion dialog! Dismissing..." -ForegroundColor Red
        $foundAssertion = $true
        
        # Try to close the dialog
        foreach ($win in $assertionWindows) {
            try {
                $win.CloseMainWindow() | Out-Null
                Start-Sleep -Milliseconds 100
                if (!$win.HasExited) {
                    $win.Kill()
                }
            } catch {
                # Ignore errors
            }
        }
    }

    # Check stderr for corruption messages
    $currentStderr = $stderrBuilder.ToString()
    if ($currentStderr -match "HEAP-CORRUPTION") {
        Write-Host "[TEST] HEAP CORRUPTION DETECTED!" -ForegroundColor Red
        $foundCorruption = $true
        break
    }

    Start-Sleep -Milliseconds 100
}

# Stop the process if still running
if (!$process.HasExited) {
    Write-Host "[TEST] Stopping process..." -ForegroundColor Yellow
    $process.Kill()
    $process.WaitForExit(5000)
}

# Cleanup event handlers
Unregister-Event -SourceIdentifier $stdoutEvent.Name
Unregister-Event -SourceIdentifier $stderrEvent.Name
Remove-Job -Name $stdoutEvent.Name -Force
Remove-Job -Name $stderrEvent.Name -Force

# Save output to files
$stdoutBuilder.ToString() | Out-File -FilePath $outputFile -Encoding UTF8
$stderrBuilder.ToString() | Out-File -FilePath $stderrFile -Encoding UTF8

Write-Host "`n[TEST] ========== TEST RESULTS ==========" -ForegroundColor Cyan
Write-Host "[TEST] Output saved to: $outputFile" -ForegroundColor Green
Write-Host "[TEST] Stderr saved to: $stderrFile" -ForegroundColor Green

if ($foundCorruption) {
    Write-Host "[TEST] STATUS: HEAP CORRUPTION DETECTED!" -ForegroundColor Red
    Write-Host "[TEST] Check $stderrFile for corruption details" -ForegroundColor Yellow
    
    # Extract corruption details
    $corruptionLines = $stderrBuilder.ToString() -split "`n" | Where-Object { $_ -match "HEAP-CORRUPTION" }
    Write-Host "`n[TEST] Corruption Details:" -ForegroundColor Red
    $corruptionLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    
} elseif ($foundAssertion) {
    Write-Host "[TEST] STATUS: ASSERTION FAILURE (but no corruption detected before it)" -ForegroundColor Yellow
    Write-Host "[TEST] This means corruption happened AFTER last check" -ForegroundColor Yellow
    
} else {
    Write-Host "[TEST] STATUS: No corruption or assertion detected" -ForegroundColor Green
}

Write-Host "[TEST] ======================================`n" -ForegroundColor Cyan

# Search for specific patterns in stderr
Write-Host "[TEST] Analyzing stderr for patterns..." -ForegroundColor Cyan
$stderr = $stderrBuilder.ToString()

if ($stderr -match "Assertion failed.*o1heap") {
    Write-Host "[TEST] Found o1heap assertion failure" -ForegroundColor Red
}

if ($stderr -match "HEAP-CORRUPTION") {
    Write-Host "[TEST] Found heap corruption message" -ForegroundColor Red
    
    # Extract the hex dumps
    $lines = $stderr -split "`n"
    $inExpected = $false
    $inActual = $false
    
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match "Expected first 64 bytes") {
            $inExpected = $true
            Write-Host "`n[TEST] Expected bytes:" -ForegroundColor Cyan
        } elseif ($lines[$i] -match "Actual first 64 bytes") {
            $inExpected = $false
            $inActual = $true
            Write-Host "`n[TEST] Actual bytes:" -ForegroundColor Cyan
        } elseif ($inExpected -or $inActual) {
            if ($lines[$i] -match "^\s+\[") {
                Write-Host "  $($lines[$i])" -ForegroundColor Yellow
            } else {
                $inExpected = $false
                $inActual = $false
            }
        }
    }
}

Write-Host "`n[TEST] Test complete!" -ForegroundColor Green

