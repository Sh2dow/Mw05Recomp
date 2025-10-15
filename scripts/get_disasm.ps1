$json = (Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x82441D40&count=20').Content | ConvertFrom-Json
$json.disasm | ForEach-Object {
    Write-Host ("{0}  {1}" -f $_.ea, $_.text)
}

