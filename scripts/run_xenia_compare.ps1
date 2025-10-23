# Run MW05 in Xenia and capture logs for comparison with recompiler
# This helps identify what system calls/events the game expects

param(
    [int]$Duration = 30  # Run for 30 seconds by default
)

$ErrorActionPreference = "Stop"

# Paths
$xeniaPath = "f:\XBox\xenia-canary\xenia_canary.exe"
$gamePath = "out\build\x64-Clang-Debug\Mw05Recomp\game\default.xex"
$logPath = "traces\xenia_compare.log"

# Check if Xenia exists
if (-not (Test-Path $xeniaPath)) {
    Write-Host "[ERROR] Xenia not found at: $xeniaPath" -ForegroundColor Red
    exit 1
}

# Check if game exists
if (-not (Test-Path $gamePath)) {
    Write-Host "[ERROR] Game not found at: $gamePath" -ForegroundColor Red
    exit 1
}

# Create traces directory
New-Item -ItemType Directory -Force -Path "traces" | Out-Null

Write-Host "[START] Running MW05 in Xenia for $Duration seconds..." -ForegroundColor Green
Write-Host "[XENIA] Path: $xeniaPath"
Write-Host "[GAME] Path: $gamePath"
Write-Host "[LOG] Output: $logPath"

# Run Xenia with logging enabled
$xeniaArgs = @(
    $gamePath,
    "--log_file=$logPath",
    "--log_level=2"  # Verbose logging
)

$process = Start-Process -FilePath $xeniaPath -ArgumentList $xeniaArgs -PassThru -NoNewWindow

Write-Host "[RUNNING] Xenia PID: $($process.Id)"
Write-Host "[WAIT] Running for $Duration seconds..."

# Wait for specified duration
Start-Sleep -Seconds $Duration

# Kill Xenia
Write-Host "[KILL] Stopping Xenia..."
Stop-Process -Id $process.Id -Force

Write-Host "[DONE] Log saved to: $logPath" -ForegroundColor Green

# Show summary of what happened
if (Test-Path $logPath) {
    $logSize = (Get-Item $logPath).Length / 1MB
    Write-Host "[LOG] Size: $([math]::Round($logSize, 2)) MB"
    
    # Search for key events
    Write-Host "`n[ANALYSIS] Key events in Xenia log:"
    
    $patterns = @(
        "XamUserGetSigninState",
        "XamUserGetXUID",
        "XamInputGetState",
        "XamNotifyCreateListener",
        "XNotifyGetNext",
        "NtCreateFile",
        "NtReadFile",
        "VdSwap",
        "VdSetGraphicsInterruptCallback"
    )
    
    foreach ($pattern in $patterns) {
        $count = (Select-String -Path $logPath -Pattern $pattern -AllMatches).Count
        if ($count -gt 0) {
            Write-Host "  $pattern : $count calls" -ForegroundColor Cyan
        }
    }
}

Write-Host "`n[NEXT] Compare with recompiler logs in traces/auto_test_stderr.txt"

