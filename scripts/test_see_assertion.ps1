$env:MW05_XEX_PATH = "D:/Games/Xbox360/NFS Most Wanted/default.xex"
$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"

# Enable file I/O and streaming bridge logging
$env:MW05_FILE_LOG = "1"
$env:MW05_STREAM_BRIDGE = "1"
$env:MW05_STREAM_FALLBACK_BOOT = "1"
$env:MW05_HOST_TRACE_HOSTOPS = "1"

# Disable video thread force-creation (causes crash)
$env:MW05_FORCE_VIDEO_THREAD = "0"
$env:MW05_FORCE_VIDEO_WORK_FLAG = "0"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

Write-Host "Starting game - WATCH FOR ASSERTION MESSAGEBOX!" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Cyan

# Start the game and wait
Start-Process -FilePath $exePath -NoNewWindow -Wait

