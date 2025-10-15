$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'
for ($i = 0; $i -lt $lines.Count; $i++) {
    # Skip import table entries (lines starting with "   F " or "   V ")
    if ($lines[$i] -match 'VdSwap' -and $lines[$i] -notmatch '^   [FV] ') {
        $start = [Math]::Max(0, $i - 20)
        $end = [Math]::Min($lines.Count - 1, $i + 5)
        $lines[$start..$end] | Out-String
        break
    }
}

