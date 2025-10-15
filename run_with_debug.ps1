# Log directory for debug outputs
$LogDir = ".\out\build\x64-Clang-Debug\Mw05Recomp"

# Try unblocking main thread to see if game progresses to graphics init
$env:MW05_BREAK_82813514 = "0"                           # DISABLED: Let worker thread run continuously
$env:MW05_FAKE_ALLOC_SYSBUF = "1"                        # ESSENTIAL: Fake system buffer allocation
$env:MW05_UNBLOCK_MAIN = "1"                             # Try unblocking main thread
$env:MW05_TRACE_KERNEL = "1"                             # Enable kernel tracing
$env:MW05_HOST_TRACE_IMPORTS = "1"                       # Enable import tracing to file
$env:MW05_TRACE_HEAP = "1"                               # Enable heap tracing
$env:MW05_BREAK_SLEEP_LOOP = "1"                    # Break sleep loop in sub_8262F2A0 after a few iterations
$env:MW05_BREAK_SLEEP_AFTER = "5"
$env:MW05_FORCE_RENDER_THREADS = "1"                # CRITICAL: Force creation of render threads


# Disable all other interventions
$env:MW05_VBLANK_VDSWAP = "0"
$env:MW05_KICK_VIDEO = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS = "0"
$env:MW05_FORCE_PRESENT = "0"
$env:MW05_FORCE_PRESENT_BG = "0"
$env:MW05_VDSWAP_NOTIFY = "0"
$env:MW05_FAST_BOOT = "0"
$env:MW05_FAST_RET = "0"
# DISABLED: These were only needed during early boot, now they cause infinite loops in frame update
# $env:MW05_BREAK_CRT_INIT = "1"
# $env:MW05_BREAK_8262DD80 = "1"                     # Break string formatting loop at 0x8262DD80
$env:MW05_FORCE_VD_INIT = "1"                      # Force graphics device initialization via CreateDevice
$env:MW05_TRACE_INDIRECT = "0"
$env:MW05_TITLE_STATE_TRACE = "1"
$env:MW05_BREAK_WAIT_LOOP = "0"
$env:MW05_FORCE_VIDEO_THREAD = "0"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "0"
$env:MW05_DEFAULT_VD_ISR = "0"
$env:MW05_REGISTER_DEFAULT_VD_ISR = "0"
$env:MW05_PULSE_VD_ON_SLEEP = "0"
$env:MW05_PRESENT_HEARTBEAT_MS = "0"
$env:MW05_STREAM_BRIDGE = "0"
$env:MW05_STREAM_FALLBACK_BOOT = "0"
$env:MW05_STREAM_ACK_NO_PATH = "0"
$env:MW05_LOOP_TRY_PM4_PRE = "0"
$env:MW05_LOOP_TRY_PM4_POST = "0"
$env:MW05_INNER_TRY_PM4 = "0"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_SET_PRESENT_CB = "1"
$env:MW05_VD_ISR_SWAP_PARAMS = "0"   # ORIGINAL order: r3=source, r4=context
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "1"
# Aggressively call present from ISR on every source==0 to validate pipeline
$env:MW05_FORCE_PRESENT_EVERY_ZERO = "1"
# Poke present periodically on source==0 and once on first zero to sanity-check
$env:MW05_FORCE_PRESENT_ON_ZERO = "1"
$env:MW05_FORCE_PRESENT_ON_FIRST_ZERO = "1"

# Seed r3 (scheduler/context) EA from the monitored ctx+0x2894 value
$env:MW05_SCHED_R3_EA = "0x00260370"
# Optionally kick PM4 builders once after present wrapper returns
$env:MW05_FPW_KICK_PM4 = "1"

# Force-create the render thread that issues draw commands
$env:MW05_FORCE_RENDER_THREAD = "1"
$env:MW05_FORCE_RENDER_THREAD_DELAY_TICKS = "150"  # Wait for graphics init to complete
$env:MW05_RENDER_THREAD_ENTRY = "0x825AA970"       # From Xenia log
$env:MW05_RENDER_THREAD_CTX = "0x40009D2C"         # CORRECT context from Xenia (was 0x7FEA17B0)

# Signal the VD interrupt event to wake up the render thread
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT = "1"
$env:MW05_PULSE_VD_EVENT_ON_SLEEP = "1"

# Enable PM4 state application (render target, viewport, scissor)
$env:MW05_PM4_APPLY_STATE = "1"

# APPROACH A: Force the flag at r31+10434 that gates present calls in the render thread
$env:MW05_FORCE_PRESENT_FLAG = "1"

# APPROACH B: Force-call present function periodically (every 60 source==0 callbacks)
$env:MW05_FORCE_PRESENT_ON_ZERO = "1"  # Already exists, enable it
$env:MW05_FORCE_PRESENT_EVERY_ZERO = "0"  # Too aggressive, keep disabled

# APPROACH C: Call present function directly from ISR (every 10 source==0 callbacks)
$env:MW05_ISR_CALL_PRESENT = "1"
$env:MW05_ISR_PRESENT_INTERVAL = "10"  # Call every 10 frames (~166ms at 60Hz)



# NOTE: Use cmd.exe to run the executable so environment variables are inherited
Write-Host "Starting game with environment variables..."
$stderrPath = ".\out\build\x64-Clang-Debug\Mw05Recomp\debug_stderr.txt"

# Clear old stderr
if (Test-Path $stderrPath) {
    Remove-Item $stderrPath -Force
}

# Run via cmd.exe which inherits environment variables
$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c run_with_env.cmd" -PassThru -WindowStyle Hidden

Write-Host "Game started with PID $($process.Id). Waiting 60 seconds..."
Start-Sleep -Seconds 60

# Kill the process and any child processes
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
if (!$process.HasExited) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

# Analyze the trace log instead of stderr
$traceLog = "$LogDir\mw05_host_trace.log"
Write-Host "`n=== TRACE LOG ANALYSIS ==="
if (Test-Path $traceLog) {
    $beginCount = (Get-Content $traceLog -ErrorAction SilentlyContinue | Select-String "BeginCommandList").Count
    $procBeginCount = (Get-Content $traceLog -ErrorAction SilentlyContinue | Select-String "ProcBeginCommandList").Count
    $applyCount = (Get-Content $traceLog -ErrorAction SilentlyContinue | Select-String "ApplyColorSurface").Count
    $fileIOCount = (Get-Content $traceLog -ErrorAction SilentlyContinue | Select-String "NtCreateFile|NtOpenFile|NtReadFile").Count
    Write-Host "BeginCommandList calls: $beginCount"
    Write-Host "ProcBeginCommandList calls: $procBeginCount"
    Write-Host "ApplyColorSurface calls: $applyCount"
    Write-Host "File I/O calls: $fileIOCount"
} else {
    Write-Host "Trace log not found at $traceLog"
}

