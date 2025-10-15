# Find when new threads appear in the trace
$tracePath = "..\Traces\file_trace.log"

if (!(Test-Path $tracePath)) {
    Write-Host "Trace file not found: $tracePath" -ForegroundColor Red
    exit 1
}

Write-Host "Finding thread transitions in file_trace.log..." -ForegroundColor Cyan

$seenTids = @{}
$lineNum = 0

Get-Content $tracePath | ForEach-Object {
    $lineNum++
    if ($_ -match 'tid=([0-9a-f]+)') {
        $tid = $matches[1]
        if (!$seenTids.ContainsKey($tid)) {
            $seenTids[$tid] = $lineNum
            Write-Host ("Line {0,6}: First appearance of tid={1}" -f $lineNum, $tid) -ForegroundColor Green
            Write-Host "  $_" -ForegroundColor Gray
        }
    }
}

Write-Host "`nTotal unique threads: $($seenTids.Count)" -ForegroundColor Yellow

