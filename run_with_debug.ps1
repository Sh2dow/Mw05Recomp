# Copy ALL environment variables from run_game.ps1
$env:MW05_VBLANK_VDSWAP = "0"
$env:MW05_KICK_VIDEO = "1"
$env:MW05_FORCE_PRESENT_WRAPPER_ONCE = "0"
$env:MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS = "60"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_PRESENT_BG = "1"
$env:MW05_VDSWAP_NOTIFY = "1"
$env:MW05_FAST_BOOT = "1"
$env:MW05_FAST_RET = "0"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_TRACE_INDIRECT = "1"
$env:MW05_FAKE_ALLOC_SYSBUF = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_FORCE_VIDEO_THREAD = "1"
$env:MW05_FORCE_VIDEO_THREAD_TICK = "300"
$env:MW05_DEFAULT_VD_ISR = "1"
$env:MW05_REGISTER_DEFAULT_VD_ISR = "1"
$env:MW05_PULSE_VD_ON_SLEEP = "1"
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_PRESENT_HEARTBEAT_MS = "100"
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_STREAM_FALLBACK_BOOT = "1"
$env:MW05_STREAM_ACK_NO_PATH = "1"
$env:MW05_LOOP_TRY_PM4_PRE = "1"
$env:MW05_LOOP_TRY_PM4_POST = "1"
$env:MW05_INNER_TRY_PM4 = "1"

# CRITICAL FIX: Force graphics callback registration
# The game is stuck waiting for something before it naturally registers the callback
# Force it to register at tick 350 (after video thread init at tick 300)
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"

$p = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -RedirectStandardError ".\debug_stderr.txt"
Start-Sleep -Seconds 15
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 2
Write-Host "`n=== STDERR DEBUG OUTPUT ==="
Get-Content ".\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "RENDER-DEBUG"
Write-Host "`n=== ANALYSIS ==="
$beginCount = (Get-Content ".\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "BeginCommandList").Count
$procBeginCount = (Get-Content ".\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "ProcBeginCommandList").Count
$applyCount = (Get-Content ".\debug_stderr.txt" -ErrorAction SilentlyContinue | Select-String "ApplyColorSurface").Count
Write-Host "BeginCommandList calls: $beginCount"
Write-Host "ProcBeginCommandList calls: $procBeginCount"
Write-Host "ApplyColorSurface calls: $applyCount"

