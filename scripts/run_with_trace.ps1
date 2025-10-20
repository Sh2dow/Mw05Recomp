# Run Mw05Recomp with tracing enabled
$env:MW05_FILE_LOG = '1'
$env:MW05_TRACE_KERNEL = '1'

# Kill any existing instances
Get-Process -Name 'Mw05Recomp' -ErrorAction SilentlyContinue | Stop-Process -Force

# Run the game for 3 seconds
$proc = Start-Process -FilePath 'out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe' -NoNewWindow -PassThru
Start-Sleep -Seconds 3
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

# Check for VdSwap messages
Write-Host "`n=== Checking for VdSwap.after_present and WB_CHECK messages ===" -ForegroundColor Cyan
Get-Content 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log' | Select-String 'VdSwap.after_present|WB_CHECK' | Select-Object -First 10

