# Run MW05 for ~15 seconds with forced video-thread init and optional natural prod
# - Avoids MW05_UNBLOCK_MAIN to keep behavior closer to natural
# - Enables MW05_TRY_CALL_82548F18 to attempt the natural chain first
# - Falls back to direct call to sub_82849DE8 at the configured tick

param(
    [int]$Seconds = 15,
    [int]$TickThreshold = 250
)

Write-Host "=== MW05 FORCE VIDEO THREAD RUN ===" -ForegroundColor Cyan
Write-Host "Seconds: $Seconds  TickThreshold: $TickThreshold" -ForegroundColor Cyan

# Core env toggles
$env:MW05_UNBLOCK_MAIN = "0"
$env:MW05_FORCE_VIDEO_THREAD = "1"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "$TickThreshold"
$env:MW05_TRY_CALL_82548F18 = "1"
$env:MW05_FORCE_VD_INIT = "1"

# Drive ISR via host default (safe bring-up)
$env:MW05_REGISTER_DEFAULT_VD_ISR = "1"
$env:MW05_DEFAULT_VD_ISR = "1"
# Optional context override to discovered scheduler (safer ISR context)
$env:MW05_VD_ISR_CTX_SCHED = "1"

# Force-create render thread late in bring-up
$env:MW05_FORCE_RENDER_THREAD = "1"
$env:MW05_FORCE_RENDER_THREAD_DELAY_TICKS = "400"

# Force-register the game's graphics notify/ISR callback and allow guest ISR dispatch
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "400"
$env:MW05_VBLANK_CB_FORCE = "1"

# Helpful tracing
# Optional nudges from ISR to build PM4
$env:MW05_ISR_TRY_BUILDER = "1"

$env:MW05_TRACE_KERNEL = "1"
$env:MW05_HOST_TRACE_IMPORTS = "1"

# Clean previous logs
$stderrPath = Join-Path "." "debug_stderr_force_video_thread.txt"
if (Test-Path $stderrPath) { Remove-Item $stderrPath -Force }
$tracePath = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
if (Test-Path $tracePath) { Remove-Item $tracePath -Force }

# Start and time-bound the run
$exePath = "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Executable not found: $exePath"
    exit 1
}

Write-Host "Starting game..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $exePath -PassThru -RedirectStandardError $stderrPath
Start-Sleep -Seconds $Seconds
if (-not $proc.HasExited) { $proc.Kill() }

# Summaries
Write-Host "`n=== SUMMARY (stderr) ===" -ForegroundColor Cyan
if (Test-Path $stderrPath) {
    Get-Content $stderrPath | Select-String "VBLANK|Vd|PM4_ScanLinear|VBLANK-FORCE|VBLANK-NATURAL|HOST.ForceVideoThread" | Select-Object -Last 50
} else {
    Write-Host "No stderr captured" -ForegroundColor Yellow
}

Write-Host "`n=== PM4 draws check ===" -ForegroundColor Cyan
if (Test-Path $stderrPath) {
    $nonZero = Get-Content $stderrPath | Select-String "draws=[1-9]"
    if ($nonZero) {
        Write-Host "FOUND NON-ZERO DRAWS!" -ForegroundColor Green
        $nonZero | Select-Object -First 20
    } else {
        Write-Host "No non-zero draws yet" -ForegroundColor Yellow
    }
}

Write-Host "`n=== Last 20 kernel trace lines ===" -ForegroundColor Cyan
if (Test-Path $tracePath) {
    Get-Content $tracePath | Select-Object -Last 20
}

