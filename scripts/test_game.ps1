Write-Host "Starting game for 90 seconds..." -ForegroundColor Green

$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -PassThru -RedirectStandardError "test_run.log" -NoNewWindow

Start-Sleep -Seconds 90

if (!$proc.HasExited) {
    Write-Host "Game still running after 90 seconds - stopping..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force
    Write-Host "SUCCESS: Game ran for 90 seconds without crashing!" -ForegroundColor Green
} else {
    Write-Host "Game exited with code: $($proc.ExitCode)" -ForegroundColor Red
}

Write-Host "`nChecking for crashes in log..." -ForegroundColor Cyan
$crashes = Get-Content "test_run.log" | Select-String "crash|CRASH|Exception|violation"
if ($crashes) {
    Write-Host "Found crash messages:" -ForegroundColor Red
    $crashes | Select-Object -First 10
} else {
    Write-Host "No crash messages found!" -ForegroundColor Green
}

