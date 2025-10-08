$funcs = @('823AF5CC', '823AF5D4', '823AF628', '823AF62C', '823AF63C', '823AF654', '823AF68C', '823AF6A4', '823AF6A8', '823AF6AC', '823AF6B0', '823AF6B4', '823AF718', '823AF728')
foreach ($f in $funcs) {
    $count = (Select-String -Path 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log' -Pattern $f | Measure-Object).Count
    Write-Host "$f : $count"
}

