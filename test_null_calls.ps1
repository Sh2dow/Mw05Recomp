$timeout = 30
$start = Get-Date

& 'D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe' 2>&1 | ForEach-Object {
    if ((Get-Date) -gt $start.AddSeconds($timeout)) {
        break
    }
    $_
} | Select-String 'NULL-CALL|BOOT.*82A2D1AC'

