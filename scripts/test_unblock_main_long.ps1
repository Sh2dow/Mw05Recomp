# Test script: Run game for 2 minutes with MW05_UNBLOCK_MAIN enabled

$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_PM4_TRACE = "1"
$env:MW05_TRACE_RB_WRITES = "1"

Write-Host "Starting game with MW05_UNBLOCK_MAIN=1 for 2 minutes..." -ForegroundColor Green

$proc = Start-Process -FilePath ".\out\build\x64-Clang-Release\Mw05Recomp\Mw05Recomp.exe" -PassThru

Write-Host "Waiting 120 seconds for game to run..." -ForegroundColor Cyan
Start-Sleep -Seconds 120

if (!$proc.HasExited) {
    Write-Host "Stopping game process..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

Write-Host "`nAnalyzing trace log..." -ForegroundColor Cyan

$logPath = ".\out\build\x64-Clang-Release\Mw05Recomp\mw05_host_trace.log"

Write-Host "`nTotal lines:" -ForegroundColor Yellow
Get-Content -Path $logPath | Measure-Object -Line

Write-Host "`nRing buffer initialization:" -ForegroundColor Yellow
Select-String -Path $logPath -Pattern "VdInitializeRingBuffer|PM4.SetRingBuffer" | Select-Object -First 5

Write-Host "`nRing buffer writes:" -ForegroundColor Yellow
$rbWrites = Select-String -Path $logPath -Pattern "RB.write"
if ($rbWrites) {
    $rbWrites | Select-Object -First 20
    Write-Host "Total RB writes: $($rbWrites.Count)" -ForegroundColor Green
} else {
    Write-Host "NO RING BUFFER WRITES DETECTED" -ForegroundColor Red
}

Write-Host "`nVideoPresent calls:" -ForegroundColor Yellow
$presents = Select-String -Path $logPath -Pattern "VideoPresent"
Write-Host "Total presents: $($presents.Count)" -ForegroundColor Green

Write-Host "`nMain thread activity (last 20 lines):" -ForegroundColor Yellow
Select-String -Path $logPath -Pattern "tid=8900.*lr=0x82441" | Select-Object -Last 20

