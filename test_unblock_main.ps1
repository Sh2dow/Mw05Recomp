# Test script: Enable MW05_UNBLOCK_MAIN to manually set the flag that the main thread is waiting for

$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_TRACE_KERNEL = "1"
$env:MW05_PM4_TRACE = "1"

Write-Host "Starting game with MW05_UNBLOCK_MAIN=1..." -ForegroundColor Green
Write-Host "This will manually set dword_82A2CF40 to 1 to unblock the main thread." -ForegroundColor Yellow

$proc = Start-Process -FilePath ".\out\build\x64-Clang-Release\Mw05Recomp\Mw05Recomp.exe" -PassThru

Write-Host "Waiting 60 seconds for game to run..." -ForegroundColor Cyan
Start-Sleep -Seconds 60

if (!$proc.HasExited) {
    Write-Host "Stopping game process..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Seconds 2
}

Write-Host "`nChecking for UnblockMainThreadEarly trace..." -ForegroundColor Cyan
Select-String -Path ".\out\build\x64-Clang-Release\Mw05Recomp\mw05_host_trace.log" -Pattern "UnblockMainThreadEarly" | Select-Object -Last 5

Write-Host "`nChecking if main thread progressed past the wait loop..." -ForegroundColor Cyan
Write-Host "Looking for function calls after the flag was set..." -ForegroundColor Yellow
$unblockLine = (Select-String -Path ".\out\build\x64-Clang-Release\Mw05Recomp\mw05_host_trace.log" -Pattern "UnblockMainThreadEarly" | Select-Object -First 1).LineNumber
if ($unblockLine) {
    Write-Host "Flag was set at line $unblockLine" -ForegroundColor Green
    Write-Host "Showing next 50 lines after flag was set:" -ForegroundColor Cyan
    Get-Content -Path ".\out\build\x64-Clang-Release\Mw05Recomp\mw05_host_trace.log" | Select-Object -Skip $unblockLine -First 50
} else {
    Write-Host "UnblockMainThreadEarly was not called!" -ForegroundColor Red
}

Write-Host "`nChecking for PM4 draw commands..." -ForegroundColor Cyan
Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "PM4.DRAW" | Select-Object -Last 10

