$lines = Select-String -Path 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log' -Pattern 'lr=0x823AF598'
$threads = @{}
foreach ($line in $lines) {
    if ($line -match 'tid=([0-9a-f]+)') {
        $tid = $matches[1]
        if (-not $threads.ContainsKey($tid)) {
            $threads[$tid] = 0
        }
        $threads[$tid]++
    }
}

Write-Host "Threads that executed code in sub_823AF590:"
foreach ($tid in $threads.Keys | Sort-Object) {
    Write-Host "  Thread $tid : $($threads[$tid]) times"
}

