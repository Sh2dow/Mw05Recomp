# Run Xenia with detailed tracing to capture initialization sequence
# This script runs Xenia for 30 seconds and captures all output

$xeniaPath = "f:\XBox\xenia-canary\xenia_canary.exe"
$xexPath = "F:\XBox\ISO\MWEurope\default.xex"
$logPath = "D:\Repos\Games\Mw05Recomp\tools\xenia_detailed.log"

Write-Host "[*] Starting Xenia with detailed tracing..."
Write-Host "[*] XEX: $xexPath"
Write-Host "[*] Log: $logPath"

# Kill any existing Xenia processes
Get-Process xenia_canary -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Run Xenia with tracing
$process = Start-Process -FilePath $xeniaPath `
    -ArgumentList "--log_file=$logPath", "--log_level=2", $xexPath `
    -PassThru `
    -NoNewWindow

Write-Host "[*] Xenia started (PID: $($process.Id))"
Write-Host "[*] Waiting 30 seconds for initialization..."

Start-Sleep -Seconds 30

Write-Host "[*] Stopping Xenia..."
Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

Write-Host "[*] Trace complete!"
Write-Host "[*] Log saved to: $logPath"

# Check log size
if (Test-Path $logPath) {
    $size = (Get-Item $logPath).Length / 1MB
    Write-Host "[*] Log size: $([math]::Round($size, 2)) MB"
}

