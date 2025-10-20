$addr = $args[0]
$count = if ($args.Length -gt 1) { $args[1] } else { 20 }

$response = Invoke-WebRequest -Uri "http://127.0.0.1:5050/disasm?ea=$addr&count=$count"
$data = $response.Content | ConvertFrom-Json

$data.disasm | ForEach-Object {
    $ea = [uint32]("0x" + $_.ea)
    Write-Host ("{0:X8}  {1}" -f $ea, $_.text)
}

