$lines = Get-Content 'tools/xenia.log'

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'Draw opcode=PM4_DRAW') {
        Write-Host "First draw at line $i"
        Write-Host ""
        Write-Host "=== 30 lines before first draw ==="
        $start = [Math]::Max(0, $i - 30)
        $end = [Math]::Min($lines.Count - 1, $i + 10)
        $lines[$start..$end] | ForEach-Object { Write-Host $_ }
        break
    }
}

