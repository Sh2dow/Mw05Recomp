# Test script: Run Debug build with MW05_UNBLOCK_MAIN for 30 seconds

$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_PM4_TRACE = "1"
$env:MW05_TRACE_RB_WRITES = "1"

Write-Host "Starting DEBUG game for 30 seconds..." -ForegroundColor Green

$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru

Write-Host "Waiting 30 seconds..." -ForegroundColor Cyan
Start-Sleep -Seconds 30

if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

Write-Host "`nAnalyzing log..." -ForegroundColor Cyan

$logPath = ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log"

Write-Host "`nUnblockThread messages:" -ForegroundColor Yellow
Select-String -Path $logPath -Pattern "UnblockThread" | Select-Object -First 10

Write-Host "`nMain thread activity (last 10 lines):" -ForegroundColor Yellow
Select-String -Path $logPath -Pattern "tid=.*lr=0x82441" | Select-Object -Last 10

