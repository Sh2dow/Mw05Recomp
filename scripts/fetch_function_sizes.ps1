# Fetch function sizes from IDA Pro HTTP server
param(
    [string]$IDAServer = "http://127.0.0.1:5050"
)

$functions = @(
    @{ addr = 0x8211E470; name = "sub_8211E470" },
    @{ addr = 0x8211E3E0; name = "sub_8211E3E0" },
    @{ addr = 0x8211E3E8; name = "sub_8211E3E8" },
    @{ addr = 0x8211E538; name = "sub_8211E538" },
    @{ addr = 0x8211F4A0; name = "sub_8211F4A0" }
)

Write-Host "Fetching function sizes from IDA Pro..." -ForegroundColor Green
Write-Host ""

$results = @()

foreach ($func in $functions) {
    $addr = $func.addr
    $name = $func.name
    
    Write-Host "Fetching $name at 0x$($addr.ToString('X8'))..." -ForegroundColor Cyan
    
    try {
        $uri = "$IDAServer/disasm?ea=0x$($addr.ToString('X8'))&count=500"
        $response = Invoke-WebRequest -Uri $uri -ErrorAction Stop
        $data = $response.Content | ConvertFrom-Json
        
        if ($data.disasm -and $data.disasm.Count -gt 0) {
            $firstAddr = [uint32]('0x' + $data.disasm[0].ea)
            $lastAddr = [uint32]('0x' + $data.disasm[-1].ea)
            
            # Calculate size (last instruction address + 4 bytes for typical instruction)
            $size = $lastAddr - $firstAddr + 4
            
            Write-Host "  Start: 0x$($firstAddr.ToString('X8'))"
            Write-Host "  End:   0x$($lastAddr.ToString('X8'))"
            Write-Host "  Size:  0x$($size.ToString('X')) ($size bytes)"
            Write-Host ""
            
            $results += @{
                name = $name
                addr = $addr
                size = $size
            }
        } else {
            Write-Host "  ERROR: No disassembly data returned" -ForegroundColor Red
        }
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
    }
}

Write-Host "Summary for TOML:" -ForegroundColor Green
Write-Host ""
foreach ($result in $results) {
    Write-Host "{ address = 0x$($result.addr.ToString('X8')), size = 0x$($result.size.ToString('X')) }  # $($result.name)"
}

