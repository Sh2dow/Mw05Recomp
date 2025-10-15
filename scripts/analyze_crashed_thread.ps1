# Analyze the crashed thread activity

$tracePath = "Traces/test_trace.log"
$crashTid = "00000AE4"

if (-not (Test-Path $tracePath)) {
    Write-Host "Trace log not found at: $tracePath" -ForegroundColor Red
    exit 1
}

Write-Host "Searching for thread 0x$crashTid activity..." -ForegroundColor Yellow
Write-Host ""

$trace = Get-Content $tracePath
$threadLines = $trace | Select-String "tid=$crashTid"

Write-Host "Total lines for thread: $($threadLines.Count)" -ForegroundColor Green
Write-Host ""

if ($threadLines.Count -eq 0) {
    Write-Host "No activity found for thread 0x$crashTid" -ForegroundColor Red
    Write-Host ""
    Write-Host "Checking for thread creation..." -ForegroundColor Yellow
    $createLines = $trace | Select-String "hostTid=$crashTid"
    if ($createLines.Count -gt 0) {
        Write-Host "Thread creation found:" -ForegroundColor Green
        $createLines | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    } else {
        Write-Host "Thread creation not found!" -ForegroundColor Red
    }
    exit 0
}

Write-Host "All activity for crashed thread:" -ForegroundColor Cyan
$threadLines | ForEach-Object { Write-Host $_ -ForegroundColor White }

Write-Host ""
Write-Host "Done!" -ForegroundColor Green

