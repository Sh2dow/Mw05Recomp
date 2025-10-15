$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'
$matches = $lines | Where-Object { ($_ -match 'XAudio|XMA') -and ($_ -notmatch '^   F ') }
if ($matches) {
    Write-Host "Found audio-related calls:"
    $matches | Select-Object -First 30
} else {
    Write-Host "No audio-related calls found"
}

