$lines = Get-Content 'D:/Repos/Games/Mw05Recomp/tools/xenia.log'
$matches = $lines | Where-Object { $_ -match 'XAudioRegisterRenderDriverClient' -and $_ -notmatch '^   F ' }
if ($matches) {
    Write-Host "Found XAudioRegisterRenderDriverClient calls:"
    $matches | Select-Object -First 10
} else {
    Write-Host "No XAudioRegisterRenderDriverClient calls found (only import table entry)"
}

