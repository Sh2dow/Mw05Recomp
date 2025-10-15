# Analyze test trace to find most frequently called functions
$tracePath = "Traces\test_trace.log"

if (!(Test-Path $tracePath)) {
    Write-Host "Trace file not found: $tracePath" -ForegroundColor Red
    exit 1
}

Write-Host "Analyzing trace file: $tracePath" -ForegroundColor Cyan

# Count function calls
$functionCalls = @{}
Get-Content $tracePath | ForEach-Object {
    if ($_ -match 'import=(__imp__\w+|sub_[0-9A-F]+|HOST\.\w+)') {
        $func = $matches[1]
        if ($functionCalls.ContainsKey($func)) {
            $functionCalls[$func]++
        } else {
            $functionCalls[$func] = 1
        }
    }
}

Write-Host "`nTop 30 most frequently called functions:" -ForegroundColor Green
$functionCalls.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 30 | ForEach-Object {
    Write-Host ("{0,10} calls: {1}" -f $_.Value, $_.Key)
}

# Check for file I/O
Write-Host "`nFile I/O operations:" -ForegroundColor Yellow
$fileIO = Get-Content $tracePath | Select-String 'NtCreateFile|NtOpenFile|NtReadFile|NtWriteFile'
Write-Host "  Total file I/O calls: $($fileIO.Count)"

# Check for VdSwap
Write-Host "`nGraphics operations:" -ForegroundColor Yellow
$vdSwap = Get-Content $tracePath | Select-String 'VdSwap'
Write-Host "  VdSwap calls: $($vdSwap.Count)"

# Check for PM4 draws
$pm4Draws = Get-Content $tracePath | Select-String 'PM4.Scan.end.*draws=([1-9]\d*)'
Write-Host "  PM4 scans with draws: $($pm4Draws.Count)"

# Check for KeSetEvent spam
$keSetEvent = Get-Content $tracePath | Select-String 'ke.set'
Write-Host "  KeSetEvent calls: $($keSetEvent.Count)"

# Check for unique thread IDs
Write-Host "`nThread analysis:" -ForegroundColor Yellow
$tids = @{}
Get-Content $tracePath | ForEach-Object {
    if ($_ -match 'tid=([0-9a-f]+)') {
        $tid = $matches[1]
        if ($tids.ContainsKey($tid)) {
            $tids[$tid]++
        } else {
            $tids[$tid] = 1
        }
    }
}
Write-Host "  Unique threads: $($tids.Count)"
$tids.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
    Write-Host ("    tid={0}: {1,6} operations" -f $_.Key, $_.Value)
}

