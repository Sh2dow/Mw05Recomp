$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -NoNewWindow -PassThru
Start-Sleep -Seconds 10
Stop-Process -Id $proc.Id -Force

