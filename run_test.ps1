$env:MW05_FAKE_ALLOC_SYSBUF = "1"
$env:MW05_KICK_VIDEO = "1"
$env:MW05_FORCE_VD_INIT = "1"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW_VERBOSE = "1"
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -ArgumentList "--mwdebug --verbose" -NoNewWindow -PassThru -RedirectStandardError "crash_stderr.txt" -RedirectStandardOutput "crash_stdout.txt"
Start-Sleep -Seconds 30
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Host "=== STDOUT ===" -ForegroundColor Green
if (Test-Path "crash_stdout.txt") {
    Get-Content "crash_stdout.txt" | Select-Object -Last 50
}
Write-Host "=== STDERR ===" -ForegroundColor Yellow
if (Test-Path "crash_stderr.txt") {
    Get-Content "crash_stderr.txt" | Select-Object -Last 50
}
Write-Host "=== TRACE LOG ===" -ForegroundColor Cyan
if (Test-Path "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log") {
    Get-Content "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log" | Select-Object -Last 50
}

