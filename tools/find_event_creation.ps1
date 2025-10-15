$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'

# Find when event 0x400007E0 is created
$index = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '400007E0' -and $lines[$i] -match 'Added handle|KeInitializeEvent|NtCreateEvent') {
        $index = $i
        break
    }
}

if ($index -ge 0) {
    Write-Host "Event 0x400007E0 creation at line $index"
    Write-Host ""
    Write-Host "=== Context ==="
    $start = [Math]::Max(0, $index - 5)
    $end = [Math]::Min($lines.Count - 1, $index + 5)
    $lines[$start..$end] | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "Event 0x400007E0 creation not found, searching for first reference..."
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '400007E0') {
            Write-Host "First reference at line $i"
            $start = [Math]::Max(0, $i - 5)
            $end = [Math]::Min($lines.Count - 1, $i + 5)
            $lines[$start..$end] | ForEach-Object { Write-Host $_ }
            break
        }
    }
}

