#!/usr/bin/env pwsh
# Test render unblocking with various environment variables

Write-Host "=== RENDER UNBLOCKING TEST ===" -ForegroundColor Cyan

# Set environment variables to enable rendering
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_PRESENT = "1"
$env:MW05_PM4_SYSBUF_TO_RING = "1"
$env:MW05_PM4_BYPASS_WAITS = "1"
$env:MW05_PM4_FORCE_SYSBUF_SCAN = "1"

Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $($env:MW05_FORCE_GFX_NOTIFY_CB)"
Write-Host "  MW05_FORCE_PRESENT = $($env:MW05_FORCE_PRESENT)"
Write-Host "  MW05_PM4_SYSBUF_TO_RING = $($env:MW05_PM4_SYSBUF_TO_RING)"
Write-Host "  MW05_PM4_BYPASS_WAITS = $($env:MW05_PM4_BYPASS_WAITS)"
Write-Host "  MW05_PM4_FORCE_SYSBUF_SCAN = $($env:MW05_PM4_FORCE_SYSBUF_SCAN)"

# Clean up old logs
if (Test-Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log") {
    Remove-Item ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Force
}

Write-Host "`nRunning game for 10 seconds..." -ForegroundColor Yellow
$startTime = Get-Date

# Run the game
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" 2>&1 | Tee-Object -FilePath "test_render_output.log" | Select-String "draws=|PRESENT|GFX-CALLBACK|SysBufCopy" | Select-Object -First 100

$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds
Write-Host "`nTest completed in $($duration.ToString('F1')) seconds" -ForegroundColor Green

# Analyze results
Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

$content = Get-Content "test_render_output.log" -ErrorAction SilentlyContinue
if ($content) {
    $drawLines = $content | Select-String "draws=([0-9]+)"
    if ($drawLines) {
        Write-Host "`nDraw commands detected:" -ForegroundColor Green
        $drawLines | Select-Object -Last 5
        
        # Check for non-zero draws
        $nonZeroDraws = $content | Select-String "draws=[1-9]"
        if ($nonZeroDraws) {
            Write-Host "`n[OK] FOUND NON-ZERO DRAWS!" -ForegroundColor Green
            $nonZeroDraws | Select-Object -First 5
        } else {
            Write-Host "`n[FAIL] All draws are zero - game is not issuing draw commands" -ForegroundColor Red
        }
    }
    
    $presentLines = $content | Select-String "PRESENT"
    Write-Host "`nPresent calls: $($presentLines.Count)" -ForegroundColor Yellow
    
    $callbackLines = $content | Select-String "GFX-CALLBACK"
    Write-Host "Graphics callbacks: $($callbackLines.Count)" -ForegroundColor Yellow
}


