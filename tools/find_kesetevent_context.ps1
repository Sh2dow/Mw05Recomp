$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'

# Find the first KeSetEvent on event 0x400007E0
$index = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'KeSetEvent ea=0x400007E0') {
        $index = $i
        break
    }
}

if ($index -ge 0) {
    Write-Host "First KeSetEvent on 0x400007E0 at line $index"
    Write-Host ""
    Write-Host "=== 30 lines before KeSetEvent ==="
    $start = [Math]::Max(0, $index - 30)
    $end = $index + 5
    $lines[$start..$end] | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No KeSetEvent on 0x400007E0 found"
}

