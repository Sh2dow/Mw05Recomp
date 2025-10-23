#!/usr/bin/env pwsh
# Test what happens when MW05_DEBUG_PROFILE is NOT set

Write-Host "=== TESTING WITHOUT MW05_DEBUG_PROFILE ===" -ForegroundColor Cyan
Write-Host "This will show if the game crashes without the debug profile defaults."
Write-Host ""

# Kill any existing processes
taskkill /F /IM Mw05Recomp.exe 2>&1 | Out-Null
Start-Sleep -Seconds 1

# DO NOT SET MW05_DEBUG_PROFILE
# This means MwApplyDebugProfile() will NOT be called
# and all the default environment variables will NOT be set

Write-Host "[TEST] Starting game WITHOUT MW05_DEBUG_PROFILE..." -ForegroundColor Yellow
Write-Host "[TEST] This means NO default environment variables will be set."
Write-Host ""

$stderr_file = "traces/no_debug_profile_stderr.txt"
$process = Start-Process -FilePath "out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow -RedirectStandardError $stderr_file

Write-Host "[TEST] Game started, PID=$($process.Id)" -ForegroundColor Green
Write-Host "[TEST] Waiting 10 seconds to see if it crashes..."

Start-Sleep -Seconds 120

if ($process.HasExited) {
    Write-Host ""
    Write-Host "[CRASH] Game CRASHED! Exit code: $($process.ExitCode)" -ForegroundColor Red
    Write-Host "[CRASH] This confirms that MW05_DEBUG_PROFILE is REQUIRED!" -ForegroundColor Red
} else {
    Write-Host ""
    Write-Host "[OK] Game still running after 10 seconds" -ForegroundColor Green
    Write-Host "[OK] Stopping game..."
    Stop-Process -Id $process.Id -Force 2>&1 | Out-Null
}

# Check stderr
if (Test-Path $stderr_file) {
    Write-Host ""
    Write-Host "=== STDERR OUTPUT ===" -ForegroundColor Cyan
    $lines = Get-Content $stderr_file
    
    # Check for crashes
    $crash_lines = $lines | Select-String "ABORT|Exception|Assertion failed|crash"
    if ($crash_lines) {
        Write-Host "[CRASH DETECTED]" -ForegroundColor Red
        $crash_lines | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    }
    
    Write-Host ""
    Write-Host "Last 30 lines:" -ForegroundColor Yellow
    $lines | Select-Object -Last 30 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "[ERROR] Stderr file not found: $stderr_file" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== CONCLUSION ===" -ForegroundColor Cyan
Write-Host "If the game crashed, then MW05_DEBUG_PROFILE is REQUIRED."
Write-Host "This is because MwApplyDebugProfile() sets critical default environment variables."

