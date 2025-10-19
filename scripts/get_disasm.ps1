$data = (Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x82596110&count=100').Content | ConvertFrom-Json
$data.disasm | ForEach-Object {
    '{0:X8}  {1}' -f [uint32]('0x' + $_.ea), $_.text
} | Out-File -FilePath 'sub_82596110_disasm.txt'
Write-Host 'Saved to sub_82596110_disasm.txt'

