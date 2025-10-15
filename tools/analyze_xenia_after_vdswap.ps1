$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'

# Find the first VdSwap call
$vdswapIndex = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'VdSwap' -and $lines[$i] -notmatch '^   [FV] ') {
        $vdswapIndex = $i
        break
    }
}

if ($vdswapIndex -ge 0) {
    Write-Host "First VdSwap at line $vdswapIndex"
    Write-Host ""
    Write-Host "=== 50 lines after first VdSwap ==="
    $start = $vdswapIndex + 1
    $end = [Math]::Min($lines.Count - 1, $vdswapIndex + 50)
    $lines[$start..$end] | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No VdSwap found"
}

