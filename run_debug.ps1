param(
    [switch]$WithCDB = $true,            # default on; pass -WithCDB:$false to run without debugger
    [switch]$CdbBreakOnAV = $false,      # if true, break on first-chance AV (interactive). Default: non-interactive.
    [int]$TimeoutSeconds = 120,          # 0 = no timeout; when >0 we Start-Sleep then kill
    [string]$LogFile = "run_log.txt",
    [string]$BuildDir = ".\out\build\x64-Clang-Debug\Mw05Recomp",
    [switch]$CloseOnExit = $true
)

$ErrorActionPreference = 'Stop'

# --- Locate cdb if requested ---------------------------------------------------
$cdbCandidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
    "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x86\cdb.exe",
    "${env:ProgramW6432}\Windows Kits\10\Debuggers\x64\cdb.exe",
    "${env:ProgramFiles}\Windows Kits\10\Debuggers\x64\cdb.exe",
    "${env:ProgramFiles}\Windows Kits\10\Debuggers\x86\cdb.exe"
) | Where-Object { $_ }  # drop nulls
$cdbPath = $cdbCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

# --- Symbol path for better crash diagnostics ---------------------------------
$repoRoot = Resolve-Path "."
$buildSymDir = Join-Path $repoRoot.Path "out/build/x64-Clang-Debug/Mw05Recomp"
$publicSymCache = "C:\symbols"
$ntSymPath = "srv*$publicSymCache*https://msdl.microsoft.com/download/symbols;$buildSymDir"

# --- Child process environment (isolated; doesn't pollute current session) ----
$envVars = @{
    _NT_SYMBOL_PATH                     = $ntSymPath

    # Ensure host/app logs land in WorkingDir
    MW05_AUTO_VIDEO                     = '0'
    MW05_HOST_TRACE_IMPORTS             = '1'
    MW05_HOST_TRACE_FILE                = 'mw05_host_trace.log'
    MW05_TRACE_KERNEL                   = '1'
    MW05_HOST_TRACE_HOSTOPS             = '1'
    MW05_STREAM_BRIDGE                  = '1'
    MW05_STREAM_ANY_LR                  = '1'
    MW05_STREAM_ACK_NO_PATH             = '0'
    MW05_LIST_SHIMS                     = '1'
    MW05_STREAM_DUMP                    = '0'
    MW05_FAST_BOOT                      = '0'
    MW05_FILE_LOG                       = '1'
    MW05_TRACE_INDIRECT                 = '1'
    MW05_FORCE_VD_EVENT_EA              = '0x00060DD0'
    MW05_ACK_FROM_EVENT_FIELD           = '0'
    MW05_CLEAR_SCHED_BLOCK              = '1'
    MW05_DUMP_SCHED_BLOCK               = '0'
    MW05_FORCE_VD_ISR                   = '1'
    MW05_TRACE_HEAP                     = '1'
    MW05_TRACE_LOADER_ARGS              = '1'

    MW_VERBOSE                          = '1'

    MW05_PULSE_VD_EVENT_ON_SLEEP        = '1'
    MW05_HOST_ISR_SIGNAL_VD_EVENT       = '1'
    MW05_HOST_ISR_TRACE_LAST_WAIT       = '1'
    MW05_HOST_ISR_LOG_VD_AS_LAST        = '1'
    MW05_HOST_ISR_TICK_SYSID            = '1'
    MW05_VD_POLL_DIAG                   = '1'
    MW05_FORCE_VD_INIT                  = '1'
    MW05_VBLANK_CB                      = '1'
    MW05_FORCE_ACK_WAIT                 = '0'
    MW05_ZERO_EVENT_PTR_AFTER_ACK       = '0'
    MW05_PUMP_EVENTS                    = '0'
    MW05_HOST_ISR_SCHED_CLEAR           = '0'
    MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT= '0'
    MW05_HOST_ISR_SIGNAL_VD_AS_LAST     = '0'
    MW05_BOOT_TICK                      = '1'
    MW05_VD_TOGGLE_E58                  = '0'
    MW05_VD_TOGGLE_E58_MASK             = '0x700'
    MW05_VD_TICK_E70                    = '1'
    MW05_VDSWAP_ACK                     = '0'
    MW05_VDSWAP_ACK_E68                 = '0x2'
    MW05_HOST_ISR_RB_STEP               = '0x80'
    MW05_REGISTER_DEFAULT_VD_ISR        = '1'
    MW05_DEFAULT_VD_ISR                 = '1'
    MW05_VBLANK_CB_FORCE                = '1'
    MW05_FAKE_VDSWAP                    = '0'
    MW05_FORCE_PRESENT                  = '0'
    MW05_FORCE_PRESENT_BG               = '0'

    MW05_KICK_VIDEO                     = '0'
    MW05_PM4_FAKE_SWAP                  = '0'
    MW05_PM4_FAKE_SWAP_ADDR             = '0x00060E58'
    MW05_PM4_FAKE_SWAP_OR               = '0'
    MW05_PM4_FAKE_SWAP_TOKEN_ADDR       = '0x00060E70'
    MW05_PM4_FAKE_SWAP_TOKEN_BASE       = '0xC00002F0'
    MW05_PM4_FAKE_SWAP_TOKEN_INC        = '1'
    MW05_PM4_FAKE_SWAP_TAIL             = '0'
    MW05_PM4_FAKE_SWAP2_ADDR            = '0x00060E68'
    MW05_PM4_FAKE_SWAP2_OR              = '0'
    MW05_HOST_ISR_NOTIFY_SRC_SEQ        = '0,1,2'
    MW05_VD_TOGGLE_E68                  = '1'
    MW05_AUTO_VDSWAP_HEUR               = '1'
    MW05_AUTO_VDSWAP_HEUR_DELAY         = '2'
    MW05_AUTO_VDSWAP_HEUR_ONCE          = '1'
    MW05_AUTO_VDSWAP_HEUR_E58_MASK      = '0'
    MW05_AUTO_VDSWAP_HEUR_E68_MASK      = '0x2'

    # Turn OFF all coercions/handshakes/bypasses
    MW05_TREAT_PRESENT_AS_VDSWAP        = '0'
    MW05_SYNTH_VDSWAP_ON_FLIP           = '1'
    MW05_FORCE_VDSWAP_ONCE              = '1'
    MW05_VD_E58_LOW16_FORCE             = ''
    MW05_VD_E58_MIRROR_E60_HI           = '0'
    MW05_VD_E48_LOW16_FORCE             = ''
    MW05_VD_E68_HANDSHAKE               = '0'
    MW05_VD_E68_ACK_PULSE               = '0'

    # Keep only these for visibility and stable cadence
    MW05_VD_TOKEN_ON_FLIP               = '1'
    MW05_ISR_AUTO_PRESENT               = '0'
    MW05_PM4_SWAP_DETECT                = '1'
    MW05_PM4_SWAP_PRESENT               = '1'
    MW05_VBLANK_PUMP                    = '1'
    MW05_HOST_ISR_ACK_EVENT             = '1'
    MW05_ZERO_EVENT_STATUS_AFTER_ACK    = '1'
    MW05_VD_READ_TRACE                  = '0'
    MW05_TRACE_RB_WRITES                = '1'
    MW05_PRESENT_HEARTBEAT_MS           = '250'
    MW05_PM4_TRACE                      = '1'
    MW05_PM4_SCAN_ALL                   = '1'
    MW05_PM4_ARM_RING_SCRATCH           = '1'
    MW05_PM4_SYSBUF_DUMP_ON_GET         = '1'
    MW05_PM4_SCAN_SYSBUF                = '1'

    MW05_TV_STATIC                      = '1'
    MW05_DRAW_DIAGNOSTIC                = '1'

    # Ensure main-thread unblock and sane defaults for early boot
    MW05_PULSE_E0DD0                    = '1'
    MW05_UNBLOCK_MAIN                   = '1'
    MW05_ALLOW_FLAG_CLEAR_AFTER_MS      = '300000'
    # Logging rate limits for UnblockThread (can be overridden by caller)
    MW05_UNBLOCK_LOG_MS                 = $env:MW05_UNBLOCK_LOG_MS
    MW05_UNBLOCK_LOG_MAX                = $env:MW05_UNBLOCK_LOG_MAX
    # Enable app-side debug profile self-configuration
    MW05_DEBUG_PROFILE                   = '1'

}

# --- Configure target + args (CDB or direct) ----------------------------------

# Resolve BuildDir relative to caller's CWD if needed
$callerCwd = Get-Location
if (-not [System.IO.Path]::IsPathRooted($BuildDir)) {
    $BuildDir = Join-Path $callerCwd.Path $BuildDir
}

# --- Resolve paths first -------------------------------------------------------
$LogDir  = (Resolve-Path $BuildDir).Path
$null    = New-Item -ItemType Directory -Path $LogDir -Force
$cdbLog  = Join-Path $LogDir "cdb_mw05.log"
$exePath = Join-Path $LogDir "Mw05Recomp.exe"
if (-not (Test-Path -LiteralPath $exePath)) { throw "Executable not found: $exePath" }

# --- Configure target + args (CDB or direct) ----------------------------------
[string]$file = $null
[array] $argList = @()
$useNoNewWindow = $false
$redirectIO     = $true  # only for non-CDB case

if ($WithCDB -and $cdbPath) {
    Write-Host "Running under cdb: $cdbPath" -ForegroundColor Yellow

    $file    = $cdbPath
    $argList = @(
        '-o','-g','-G',
        '-logo', $cdbLog,
        '-y', $ntSymPath
    )
    if ($CdbBreakOnAV) { $argList += @('-xe','av') } else { $argList += @('-xd','av') }
    # Non-interactive: auto-continue and quit on process end
    $argList += @('-c', 'g;qd', $exePath)

    $useNoNewWindow = $false   # give CDB its own console
    $redirectIO     = $false   # CDB already logs to -logo
}
else {
    if ($WithCDB) { Write-Host "CDB requested but not found; running without debugger..." -ForegroundColor Yellow }
    else          { Write-Host "Running without debugger..." -ForegroundColor Yellow }

    $file          = $exePath
    $argList       = @()
    $useNoNewWindow = $true
    $redirectIO     = $true    # capture game stdout/stderr
}

# --- Build Start-Process params and LAUNCH (PS5-compatible; export env to process) ----
$LogOut = Join-Path $LogDir "mw05_stdout.log"
$LogErr = Join-Path $LogDir "mw05_stderr.log"

# Export environment variables to this PowerShell session so the child inherits them
foreach ($k in $envVars.Keys) { Set-Item -Path Env:$k -Value ([string]$envVars[$k]) }

$startParams = @{
    FilePath         = $file
    WorkingDirectory = $LogDir
    PassThru         = $true
}
if ($argList -and $argList.Count -gt 0) { $startParams.ArgumentList = $argList }
if ($useNoNewWindow) { $startParams.NoNewWindow = $true }
if ($redirectIO) {
    $startParams.RedirectStandardOutput = $LogOut
    $startParams.RedirectStandardError  = $LogErr
}

Write-Host "LAUNCH: $file" -ForegroundColor Cyan
Write-Host "ARGS  : $($argList -join ' ')" -ForegroundColor Cyan
Write-Host "CWD   : $LogDir" -ForegroundColor Cyan

$p = Start-Process @startParams

$timedOut = $false
if ($TimeoutSeconds -gt 0) {
    Start-Sleep -Seconds $TimeoutSeconds
    if (-not $p.HasExited) {
        Write-Warning "Timeout after $TimeoutSeconds s - killing process..."
        $p.Kill()
        $timedOut = $true
        [void]$p.WaitForExit(2000)
    }
} else {
    $p.WaitForExit()
}


# --- Post-run summary -----------------------------------------------------------
$exitCode = $p.ExitCode
if ($timedOut) {
  Write-Host "RESULT: TIMEOUT_KILL after $TimeoutSeconds s" -ForegroundColor Yellow
} else {
  Write-Host "RESULT: EXIT code=$exitCode" -ForegroundColor Yellow
}

# Surface logs to console for quick triage
if ($WithCDB -and (Test-Path -LiteralPath $cdbLog)) {
  Write-Host "CDB LOG: $cdbLog (tail)" -ForegroundColor DarkCyan
  try { Get-Content -LiteralPath $cdbLog -Tail 40 | Write-Host } catch {}
} else {
  # Non-CDB: show stderr tail if present
  if ($redirectIO -and (Test-Path -LiteralPath $LogErr)) {
    Write-Host "STDERR: $LogErr (tail)" -ForegroundColor DarkCyan
    try { Get-Content -LiteralPath $LogErr -Tail 30 | Write-Host } catch {}
  }
}


# Always point to host trace if present
$hostTrace = Join-Path $LogDir "mw05_host_trace.log"
if (Test-Path -LiteralPath $hostTrace) {
  Write-Host "HOST TRACE: $hostTrace (last 20 lines)" -ForegroundColor DarkCyan
  try { Get-Content -LiteralPath $hostTrace -Tail 20 | Write-Host } catch {}
}


# Exit so a stand-alone window (double-click) closes automatically when requested
if ($CloseOnExit) {
  exit $exitCode
}
