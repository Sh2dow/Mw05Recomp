$env:MW05_FAKE_ALLOC_SYSBUF = "1"
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -ArgumentList "--mwdebug" -NoNewWindow -PassThru -RedirectStandardError "crash_stderr.txt"
Start-Sleep -Seconds 30
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
if (Test-Path "crash_stderr.txt") {
    Get-Content "crash_stderr.txt" | Select-Object -Last 100
}

