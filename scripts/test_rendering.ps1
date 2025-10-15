$env:MW05_FAST_BOOT = "1"
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_BREAK_82813514 = "1"
$env:MW05_BREAK_WAIT_LOOP = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"

$proc = Start-Process -FilePath 'D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe' -RedirectStandardError 'D:/Repos/Games/Mw05Recomp/test_stderr.txt' -PassThru -NoNewWindow
Start-Sleep -Seconds 30
Stop-Process -Id $proc.Id -Force
Get-Content 'D:/Repos/Games/Mw05Recomp/test_stderr.txt' | Select-String 'NULL-CALL|MW05HostAllocCb|DRAW|PM4|GFX-REG|GFX-CALLBACK' | Select-Object -First 100

