# Find which PPC function corresponds to a crash offset

param(
    [Parameter(Mandatory=$true)]
    [uint64]$CrashOffset
)

$ppcBase = 0x82000000
$ppcSize = 0x00CD0000

# Calculate estimated PPC address
# The crash offset is relative to the executable base
# PPC code starts at some offset in the executable
# We need to map the crash offset back to a PPC address

Write-Host "Crash offset: 0x$($CrashOffset.ToString('X'))" -ForegroundColor Cyan
Write-Host ""

# Read the TOML file and extract all function addresses
Write-Host "Searching for function in TOML..." -ForegroundColor Yellow
$tomlPath = "Mw05RecompLib/config/MW05.toml"

$functions = Get-Content $tomlPath | Select-String 'address = 0x[0-9A-F]+' | ForEach-Object {
    if ($_.Line -match 'address = (0x[0-9A-F]+).*size = (0x[0-9A-F]+)') {
        [PSCustomObject]@{
            Address = [Convert]::ToUInt32($matches[1], 16)
            Size = [Convert]::ToUInt32($matches[2], 16)
            Line = $_.LineNumber
            Text = $_.Line.Trim()
        }
    }
}

Write-Host "Total functions in TOML: $($functions.Count)" -ForegroundColor Green
Write-Host ""

# Try to find the function by looking at the trace log
Write-Host "Checking trace log for last function call..." -ForegroundColor Yellow
$tracePath = "Traces/test_trace.log"

if (Test-Path $tracePath) {
    # Get the last few function calls before the crash
    $lastCalls = Get-Content $tracePath | Select-String 'import=sub_[0-9A-F]{8}' | Select-Object -Last 20
    
    Write-Host "Last 20 function calls before crash:" -ForegroundColor Cyan
    $lastCalls | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    
    # Extract the last function address
    if ($lastCalls.Count -gt 0) {
        $lastCall = $lastCalls[-1]
        if ($lastCall -match 'import=sub_([0-9A-F]{8})') {
            $lastFuncAddr = [Convert]::ToUInt32($matches[1], 16)
            Write-Host "Last function called: 0x$($lastFuncAddr.ToString('X8'))" -ForegroundColor Green
            
            # Find this function in the TOML
            $func = $functions | Where-Object { $_.Address -eq $lastFuncAddr }
            if ($func) {
                Write-Host "Found in TOML:" -ForegroundColor Green
                Write-Host "  Line: $($func.Line)" -ForegroundColor White
                Write-Host "  Address: 0x$($func.Address.ToString('X8'))" -ForegroundColor White
                Write-Host "  Size: 0x$($func.Size.ToString('X'))" -ForegroundColor White
                Write-Host "  Text: $($func.Text)" -ForegroundColor White
            } else {
                Write-Host "NOT FOUND IN TOML!" -ForegroundColor Red
                Write-Host "This function needs to be added to the TOML!" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "Trace log not found at: $tracePath" -ForegroundColor Red
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green

