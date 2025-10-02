cd .\out\build\x64-Clang-Debug\Mw05Recomp

# Enable stable GPU pumping without aggressive ACK hacks
$env:MW05_DEBUG_PROFILE=0
$env:MW05_LOG_DBG_BREAK=0
$env:MW05_LIST_SHIMS=0

$env:MW05_FILE_LOG=1
$env:MW05_HOST_TRACE_IMPORTS=1
$env:MW05_HOST_TRACE_HOSTOPS=1
# PM4 tracing for draw detection
$env:MW05_PM4_TRACE=1


# Disable manual overrides and runtime patch hooks to use real recompiled bodies
$env:MW05_DISABLE_OVERRIDES=1
$env:MW05_RUNTIME_PATCHES=0

# Present on PM4 swap; allow default VD ISR to keep things moving
$env:MW05_PM4_SWAP_PRESENT=1
$env:MW05_PRESENT_HEARTBEAT_MS=250
$env:MW05_FORCE_PRESENT=0
$env:MW05_FORCE_PRESENT_BG=0

$env:MW05_REGISTER_DEFAULT_VD_ISR=1
$env:MW05_DEFAULT_VD_ISR=1
$env:MW05_PUMP_EVENTS=1
$env:MW05_HOST_ISR_TICK_SYSID=1
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT=1
$env:MW05_HOST_ISR_NOTIFY_SRC_SEQ="0,1"

# Avoid reentrant ACK hacks
$env:MW05_FORCE_ACK_WAIT=0
$env:MW05_ZERO_EVENT_PTR_AFTER_ACK=0
$env:MW05_ZERO_EVENT_STATUS_AFTER_ACK=0

# Streaming bridge stays on
$env:MW05_STREAM_BRIDGE=1

.\Mw05Recomp.exe

