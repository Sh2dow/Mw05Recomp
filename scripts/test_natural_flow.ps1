# Test script: Run game WITHOUT any workarounds to test the natural flow fix
# This tests if the VD ISR flag fix (0x7FE86544) allows the game to run naturally

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing Natural Flow (NO Workarounds)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test runs the game WITHOUT any environment variable workarounds." -ForegroundColor Yellow
Write-Host "The VD ISR flag at 0x7FE86544 should be set during initialization," -ForegroundColor Yellow
Write-Host "allowing the game to run naturally without forcing flags or callbacks." -ForegroundColor Yellow
Write-Host ""

# Log directory
$LogDir = ".\out\build\x64-Clang-Debug\Mw05Recomp"

# DISABLE ALL WORKAROUNDS - test natural flow
$env:MW05_UNBLOCK_MAIN = "0"                       # DISABLED: Let game run naturally
$env:MW05_BREAK_82813514 = "0"                     # DISABLED: Let worker thread run naturally
$env:MW05_BREAK_SLEEP_LOOP = "0"                   # DISABLED: Let sleep loop run naturally
$env:MW05_FORCE_PRESENT = "0"                      # DISABLED: Let game drive presents
$env:MW05_FORCE_GFX_NOTIFY_CB = "0"                # DISABLED: Let game register callbacks naturally
$env:MW05_FORCE_RENDER_THREAD = "0"                # DISABLED: Let game create threads naturally
$env:MW05_FORCE_VD_INIT = "0"                      # DISABLED: Let game initialize video naturally
$env:MW05_FAKE_ALLOC_SYSBUF = "1"                  # KEEP: This is a real fix for allocation
$env:MW05_TRACE_KERNEL = "1"                       # KEEP: Enable tracing to see what happens
$env:MW05_HOST_TRACE_IMPORTS = "1"                 # KEEP: Trace imports to file
# $env:MW05_REGISTER_DEFAULT_VD_ISR = "1"          # DISABLED: Now registered in code, not needed

# Disable all other force flags
$env:MW05_VBLANK_VDSWAP = "0"
$env:MW05_KICK_VIDEO = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS = "0"
$env:MW05_FORCE_PRESENT_BG = "0"
$env:MW05_VDSWAP_NOTIFY = "0"
$env:MW05_FAST_BOOT = "0"
$env:MW05_FAST_RET = "0"
$env:MW05_BREAK_WAIT_LOOP = "0"
$env:MW05_FORCE_VIDEO_THREAD = "0"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "0"
$env:MW05_DEFAULT_VD_ISR = "0"
# $env:MW05_REGISTER_DEFAULT_VD_ISR = "0"  # COMMENTED OUT: Set to "1" above to enable default VD ISR
$env:MW05_PULSE_VD_ON_SLEEP = "0"
$env:MW05_PRESENT_HEARTBEAT_MS = "0"
$env:MW05_STREAM_BRIDGE = "0"
$env:MW05_STREAM_FALLBACK_BOOT = "0"
$env:MW05_STREAM_ACK_NO_PATH = "0"
$env:MW05_LOOP_TRY_PM4_PRE = "0"
$env:MW05_LOOP_TRY_PM4_POST = "0"
$env:MW05_INNER_TRY_PM4 = "0"
$env:MW05_SET_PRESENT_CB = "0"
$env:MW05_VD_ISR_SWAP_PARAMS = "0"
$env:MW05_FORCE_PRESENT_EVERY_ZERO = "0"
$env:MW05_FORCE_PRESENT_ON_ZERO = "0"
$env:MW05_FORCE_PRESENT_ON_FIRST_ZERO = "0"
$env:MW05_FPW_KICK_PM4 = "0"
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT = "0"
$env:MW05_PULSE_VD_EVENT_ON_SLEEP = "0"
$env:MW05_PM4_APPLY_STATE = "0"
$env:MW05_FORCE_PRESENT_FLAG = "0"
$env:MW05_ISR_CALL_PRESENT = "0"
$env:MW05_ISR_PRESENT_INTERVAL = "0"

Write-Host "Environment configured (all workarounds DISABLED)" -ForegroundColor Green
Write-Host ""
Write-Host "Starting game for 20 seconds..." -ForegroundColor Yellow
Write-Host ""

# Clean up old logs
if (Test-Path "$LogDir\debug_stderr.txt") {
    Remove-Item "$LogDir\debug_stderr.txt" -Force
}
if (Test-Path "$LogDir\mw05_host_trace.log") {
    Remove-Item "$LogDir\mw05_host_trace.log" -Force
}

# Start the game
$p = Start-Process -FilePath "$LogDir\Mw05Recomp.exe" -PassThru -RedirectStandardError "$LogDir\debug_stderr.txt"

# Wait 20 seconds
Start-Sleep -Seconds 20

# Stop the game
if (!$p.HasExited) {
    Stop-Process -Id $p.Id -Force
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if VD ISR flag was set
$vdIsrFlagSet = (Get-Content "$LogDir\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "Set VD ISR flag at 0x7FC86544 to 1").Count
if ($vdIsrFlagSet -gt 0) {
    Write-Host "[OK] VD ISR flag was set during initialization" -ForegroundColor Green
} else {
    Write-Host "[FAIL] VD ISR flag was NOT set during initialization" -ForegroundColor Red
}

# Check if VD ISR callback was called
$vdIsrCalls = (Get-Content "$LogDir\mw05_host_trace.log" -ErrorAction SilentlyContinue | Select-String "VdCallGraphicsNotificationRoutines").Count
Write-Host "VD ISR callback calls: $vdIsrCalls" -ForegroundColor $(if ($vdIsrCalls -gt 0) { "Green" } else { "Red" })

# Check if main thread is running
$mainThreadRuns = (Get-Content "$LogDir\mw05_host_trace.log" -ErrorAction SilentlyContinue | Select-String "sub_8262DE60").Count
Write-Host "Main thread frame updates: $mainThreadRuns" -ForegroundColor $(if ($mainThreadRuns -gt 0) { "Green" } else { "Red" })

# Check if BeginCommandList was called
$beginCount = (Get-Content "$LogDir\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "BeginCommandList").Count
Write-Host "BeginCommandList calls: $beginCount" -ForegroundColor $(if ($beginCount -gt 0) { "Green" } else { "Red" })

# Check if draws appeared
$drawPattern = "PM4_ScanLinear result:.*draws=([0-9]+)"
$drawMatches = Get-Content "$LogDir\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String $drawPattern
if ($drawMatches) {
    $maxDraws = ($drawMatches | ForEach-Object { 
        if ($_.Line -match $drawPattern) { [int]$matches[1] } 
    } | Measure-Object -Maximum).Maximum
    Write-Host "Maximum draws in PM4 buffer: $maxDraws" -ForegroundColor $(if ($maxDraws -gt 0) { "Green" } else { "Yellow" })
} else {
    Write-Host "No PM4 scan results found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verdict" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($vdIsrFlagSet -gt 0 -and $vdIsrCalls -gt 0 -and $mainThreadRuns -gt 0) {
    Write-Host "[SUCCESS] Game is running naturally without workarounds!" -ForegroundColor Green
    Write-Host "The VD ISR flag fix is working correctly." -ForegroundColor Green
} elseif ($vdIsrFlagSet -gt 0 -and $vdIsrCalls -gt 0) {
    Write-Host "[PARTIAL] VD ISR is working, but main thread is not running" -ForegroundColor Yellow
    Write-Host "The flag at 0x82A2CF40 might not be getting set by the callback." -ForegroundColor Yellow
} elseif ($vdIsrFlagSet -gt 0) {
    Write-Host "[PARTIAL] VD ISR flag was set, but callback is not being called" -ForegroundColor Yellow
    Write-Host "The callback might not be registered yet." -ForegroundColor Yellow
} else {
    Write-Host "[FAIL] VD ISR flag was not set during initialization" -ForegroundColor Red
    Write-Host "The fix was not applied correctly." -ForegroundColor Red
}

Write-Host ""
Write-Host "Logs saved to:" -ForegroundColor Cyan
Write-Host "  - $LogDir\debug_stderr.txt" -ForegroundColor White
Write-Host "  - $LogDir\mw05_host_trace.log" -ForegroundColor White
Write-Host ""

