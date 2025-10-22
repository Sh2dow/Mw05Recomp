# Check NULL-CALL error at 0x8262FDF0

Write-Host "[DISASM] Fetching disassembly for 0x8262FDF0..." -ForegroundColor Yellow
$response = Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x8262FDF0&count=20'
$json = $response.Content | ConvertFrom-Json

Write-Host "`n[DISASM] Assembly at 0x8262FDF0:" -ForegroundColor Green
$json.disasm | Select-Object -First 20 | ForEach-Object {
    Write-Host ("  {0}  {1}" -f $_.ea, $_.text)
}

Write-Host "`n[DECOMPILE] Fetching decompilation for 0x8262FDF0..." -ForegroundColor Yellow
$response2 = Invoke-WebRequest -Uri 'http://127.0.0.1:5050/decompile?ea=0x8262FDF0'
$json2 = $response2.Content | ConvertFrom-Json

Write-Host "`n[DECOMPILE] Pseudocode:" -ForegroundColor Green
Write-Host $json2.pseudocode

