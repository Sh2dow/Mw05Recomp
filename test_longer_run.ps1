# Test script - run for 60 seconds and capture detailed stats
$ErrorActionPreference = "Continue"

Write-Host "Starting 60-second test run..." -ForegroundColor Cyan

# Start the game in background
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" `
    -WorkingDirectory "out/build/x64-Clang-Debug/Mw05Recomp" `
    -RedirectStandardError "debug_stderr_long.txt" `
    -PassThru `
    -NoNewWindow

# Wait 60 seconds
Write-Host "Waiting 60 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 60

# Kill the process
Write-Host "Stopping game..." -ForegroundColor Yellow
Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 2

# Analyze the output
Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

$stderr = Get-Content "debug_stderr_long.txt" -ErrorAction SilentlyContinue

if ($stderr) {
    # Count threads created
    $threadCount = ($stderr | Select-String "ExCreateThread returned" | Measure-Object).Count
    Write-Host "Game threads created: $threadCount" -ForegroundColor Green
    
    # Count file I/O operations
    $fileOps = ($stderr | Select-String "NtCreateFile called|NtOpenFile called|NtReadFile called" | Measure-Object).Count
    Write-Host "File I/O operations: $fileOps" -ForegroundColor Green
    
    # Count VdSwap calls
    $vdSwapCalls = ($stderr | Select-String "VdSwap called" | Measure-Object).Count
    Write-Host "VdSwap calls: $vdSwapCalls" -ForegroundColor Green
    
    # Count PM4 scans
    $pm4Scans = ($stderr | Select-String "PM4_ScanLinear called" | Measure-Object).Count
    Write-Host "PM4 scans: $pm4Scans" -ForegroundColor Green
    
    # Count draws
    $drawLines = $stderr | Select-String "draws=([0-9]+)"
    $totalDraws = 0
    foreach ($line in $drawLines) {
        if ($line -match "draws=([0-9]+)") {
            $totalDraws += [int]$matches[1]
        }
    }
    Write-Host "Total draws: $totalDraws" -ForegroundColor $(if ($totalDraws -gt 0) { "Green" } else { "Red" })
    
    # Check for MicroIB activity
    $microIBCalls = ($stderr | Select-String "Mw05InterpretMicroIB" | Measure-Object).Count
    Write-Host "MicroIB interpreter calls: $microIBCalls" -ForegroundColor Green
    
    # Check for graphics callback invocations
    $gfxCallbacks = ($stderr | Select-String "GFX-CALLBACK" | Measure-Object).Count
    Write-Host "Graphics callback invocations: $gfxCallbacks" -ForegroundColor Green
    
    # Show last 20 lines
    Write-Host "`n=== LAST 20 LINES ===" -ForegroundColor Cyan
    $stderr | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
    
    # Check for any errors or crashes
    $errors = $stderr | Select-String "ERROR|CRASH|EXCEPTION|FATAL"
    if ($errors) {
        Write-Host "`n=== ERRORS FOUND ===" -ForegroundColor Red
        $errors | Select-Object -First 10 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    }
} else {
    Write-Host "No stderr output captured!" -ForegroundColor Red
}

Write-Host "`nTest complete. Full log saved to debug_stderr_long.txt" -ForegroundColor Cyan

