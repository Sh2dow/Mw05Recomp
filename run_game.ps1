# MW05 Recompiled - Game Launcher
# This script configures all necessary environment variables to run the game

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MW05 Recompiled - Starting Game" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# CRITICAL SETTINGS - DO NOT CHANGE
# ============================================================================

# Let guest code drive rendering (NOT the host vblank pump)
$env:MW05_VBLANK_VDSWAP = "0"

# CRITICAL: Force presents until guest starts rendering
$env:MW05_KICK_VIDEO = "1"

# Force present wrapper to be called to kickstart rendering
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"  # Disabled - doesn't help
$env:MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS = "60"

# CRITICAL: Force host to drive presents continuously to at least show SOMETHING
$env:MW05_FORCE_PRESENT = "0"
$env:MW05_FORCE_PRESENT_BG = "1"

# Enable graphics notifications
$env:MW05_VDSWAP_NOTIFY = "1"

# Fast boot to skip delays
$env:MW05_FAST_BOOT = "1"
$env:MW05_FAST_RET = "0"
$env:MW05_BREAK_82813514 = "1"  # CRITICAL: Break the rendering thread wait loop
$env:MW05_TRACE_INDIRECT = "1"  # Trace indirect function calls
$env:MW05_FAKE_ALLOC_SYSBUF = "1"  # CRITICAL: Fake allocations to avoid NULL function pointer calls
$env:MW05_BREAK_WAIT_LOOP = "1"  # CRITICAL: Break the wait loop at 0x825CEE18/0x825CEE28

# Unblock main thread
$env:MW05_UNBLOCK_MAIN = "1"

# Force video thread creation
$env:MW05_FORCE_VIDEO_THREAD = "1"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "300"

# Enable default VD ISR to keep guest moving
$env:MW05_DEFAULT_VD_ISR = "1"
$env:MW05_REGISTER_DEFAULT_VD_ISR = "1"
$env:MW05_PULSE_VD_ON_SLEEP = "1"

# Enable kernel tracing to see ISR calls
$env:MW05_TRACE_KERNEL = "1"

# Present heartbeat
$env:MW05_PRESENT_HEARTBEAT_MS = "100"

# Streaming bridge
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_STREAM_FALLBACK_BOOT = "1"
$env:MW05_STREAM_ACK_NO_PATH = "1"

# PM4 processing
$env:MW05_LOOP_TRY_PM4_PRE = "1"
$env:MW05_LOOP_TRY_PM4_POST = "1"
$env:MW05_INNER_TRY_PM4 = "1"

Write-Host "[OK] Environment configured" -ForegroundColor Green
Write-Host ""
Write-Host "Launching game..." -ForegroundColor Yellow
Write-Host ""

# Run the game
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

