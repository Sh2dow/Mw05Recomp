# Test script for MW05_UNBLOCK_MAIN flag fix
# This enables both the load intercept (forcing reads to return 1) and the store intercept (blocking writes of 0)

cd .\out\build\x64-Clang-Debug\Mw05Recomp;

# Enable the main thread unblock workaround
$env:MW05_UNBLOCK_MAIN=1;

# Enable PM4 command buffer tracing
$env:MW05_PM4_TRACE=1;

# Enable draw diagnostic tracing
$env:MW05_DRAW_DIAGNOSTIC=1;

# Enable automatic video initialization (DEFAULT: ON)
# $env:MW05_AUTO_VIDEO=0;

# Enable fast boot to skip delays
$env:MW05_FAST_BOOT=1;
$env:MW05_TRACE_KERNEL=1;
$env:MW05_HOST_TRACE_IMPORTS=1;
$env:MW05_HOST_TRACE_HOSTOPS=1;
$env:MW05_FILE_LOG=1;

# Standard video/ISR settings from run_debug.ps1
$env:MW05_STREAM_BRIDGE=1;
# Aggressive: ACK stream blocks even when no path was decoded, to keep the loader advancing
$env:MW05_STREAM_ACK_NO_PATH=1;
$env:MW05_LIST_SHIMS=1;
# Keep FAST_BOOT enabled to push past early waits
$env:MW05_FAST_BOOT=1;
$env:MW05_FORCE_VD_EVENT_EA='0x00060DD0';
# Disable aggressive scheduler/ack fiddling to allow native flow
$env:MW05_ACK_FROM_EVENT_FIELD=0;
$env:MW05_CLEAR_SCHED_BLOCK=0;
$env:MW05_DUMP_SCHED_BLOCK=0;
$env:MW05_FORCE_VD_ISR=1;
$env:MW05_TRACE_HEAP=1;
$env:MW_VERBOSE=1;
$env:MW05_PULSE_VD_EVENT_ON_SLEEP=1;
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT=1;
$env:MW05_HOST_ISR_TRACE_LAST_WAIT=1;
$env:MW05_HOST_ISR_LOG_VD_AS_LAST=1;
$env:MW05_HOST_ISR_TICK_SYSID=1;
$env:MW05_VD_POLL_DIAG=1;
$env:MW05_FORCE_VD_INIT=1;
$env:MW05_VBLANK_CB=1;
$env:MW05_FORCE_ACK_WAIT=0;
$env:MW05_ZERO_EVENT_PTR_AFTER_ACK=0;
$env:MW05_PUMP_EVENTS=0;
$env:MW05_HOST_ISR_SCHED_CLEAR=0;
$env:MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT=1;
$env:MW05_HOST_ISR_SIGNAL_VD_AS_LAST=0;
$env:MW05_BOOT_TICK=1;
$env:MW05_VD_TOGGLE_E58=0;
$env:MW05_VD_TOGGLE_E58_MASK='0x700';
$env:MW05_VD_TICK_E70=1;
$env:MW05_VDSWAP_ACK=0;
$env:MW05_VDSWAP_ACK_E68='0x2';
$env:MW05_HOST_ISR_RB_STEP='0x80';
$env:MW05_REGISTER_DEFAULT_VD_ISR=1;
$env:MW05_DEFAULT_VD_ISR=1;
$env:MW05_VBLANK_CB_FORCE=1;
$env:MW05_PULSE_E0DD0=1;

$env:MW05_FAKE_VDSWAP=0;
$env:MW05_FORCE_PRESENT=0;
$env:MW05_FORCE_PRESENT_BG=0;
$env:MW05_KICK_VIDEO=0;
$env:MW05_PM4_FAKE_SWAP=0;
$env:MW05_PM4_FAKE_SWAP_ADDR='0x00060E58'
$env:MW05_PM4_FAKE_SWAP_OR=0;
$env:MW05_PM4_FAKE_SWAP_TOKEN_ADDR='0x00060E70';
$env:MW05_PM4_FAKE_SWAP_TOKEN_BASE='0xC00002F0';
$env:MW05_PM4_FAKE_SWAP_TOKEN_INC=1;
$env:MW05_PM4_FAKE_SWAP_TAIL=0;
$env:MW05_PM4_FAKE_SWAP2_ADDR='0x00060E68';
$env:MW05_PM4_FAKE_SWAP2_OR=0;
$env:MW05_HOST_ISR_NOTIFY_SRC_SEQ="0,1,2";
$env:MW05_VD_TOGGLE_E68=1;
$env:MW05_AUTO_VDSWAP_HEUR=1;
$env:MW05_AUTO_VDSWAP_HEUR_DELAY=2;
$env:MW05_AUTO_VDSWAP_HEUR_ONCE=1;
$env:MW05_AUTO_VDSWAP_HEUR_E58_MASK=0;
$env:MW05_AUTO_VDSWAP_HEUR_E68_MASK='0x2';
$env:MW05_TREAT_PRESENT_AS_VDSWAP=0;
$env:MW05_SYNTH_VDSWAP_ON_FLIP=1;
$env:MW05_FORCE_VDSWAP_ONCE=1;
$env:MW05_VD_E58_LOW16_FORCE="";
$env:MW05_VD_E58_MIRROR_E60_HI=0;
$env:MW05_VD_E48_LOW16_FORCE="";
$env:MW05_VD_E68_HANDSHAKE=0;
$env:MW05_VD_E68_ACK_PULSE=0;
$env:MW05_VD_TOKEN_ON_FLIP=1;
$env:MW05_ISR_AUTO_PRESENT=0;
$env:MW05_PM4_SWAP_DETECT=1;
$env:MW05_PM4_SWAP_PRESENT=1;
$env:MW05_VBLANK_PUMP=1;
$env:MW05_HOST_ISR_ACK_EVENT=1;
$env:MW05_ZERO_EVENT_STATUS_AFTER_ACK=1;
$env:MW05_VD_READ_TRACE=0;
$env:MW05_TRACE_RB_WRITES=1;
$env:MW05_PRESENT_HEARTBEAT_MS=250;

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing MW05_UNBLOCK_MAIN Flag Protection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This test enables the dual-protection fix for address 0x82A2CF40:" -ForegroundColor Yellow
Write-Host "  1. LoadBE32_Watched: Forces reads to return 1 (unblocks main thread)" -ForegroundColor Green
Write-Host "  2. StoreBE32_Watched: Blocks writes of 0 (prevents flag reset)" -ForegroundColor Green
Write-Host ""
Write-Host "Watch the log for these messages:" -ForegroundColor Yellow
Write-Host "  - 'HOST.LoadBE32_Watched FORCING flag ea=82A2CF40 to 1'" -ForegroundColor White
Write-Host "  - 'HOST.StoreBE32_Watched BLOCKING reset of flag ea=82A2CF40'" -ForegroundColor White
Write-Host ""
Write-Host "Starting game..." -ForegroundColor Cyan
Write-Host ""

$proc = Start-Process -FilePath ".\Mw05Recomp.exe" -PassThru

Write-Host "Waiting 60 seconds for game to run..." -ForegroundColor Cyan
Start-Sleep -Seconds 180

if (!$proc.HasExited) {
    Write-Host "Stopping game process..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}
