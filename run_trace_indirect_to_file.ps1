$env:MW05_TRACE_INDIRECT = "1"
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -NoNewWindow -PassThru -RedirectStandardError "indirect_misses.txt"
Start-Sleep -Seconds 10
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

