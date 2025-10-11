$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -RedirectStandardError "debug_stderr.txt" -NoNewWindow -PassThru
Start-Sleep -Seconds 5
Stop-Process -Id $proc.Id -Force
Get-Content "debug_stderr.txt" | Select-String "DEBUG:"

