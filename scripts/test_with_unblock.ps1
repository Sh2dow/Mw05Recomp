#!/usr/bin/env pwsh
# Test rendering with MW05_UNBLOCK_MAIN enabled

Write-Host "=== RENDER TEST WITH UNBLOCK_MAIN ===" -ForegroundColor Cyan

# Set environment variables
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_PRESENT = "1"

Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  MW05_UNBLOCK_MAIN = $($env:MW05_UNBLOCK_MAIN)"
Write-Host "  MW05_FORCE_GFX_NOTIFY_CB = $($env:MW05_FORCE_GFX_NOTIFY_CB)"
Write-Host "  MW05_FORCE_PRESENT = $($env:MW05_FORCE_PRESENT)"

Write-Host "`nRunning game for 10 seconds..." -ForegroundColor Yellow

# Run the game
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" 2>&1 | Tee-Object -FilePath "test_unblock_output.log" | Select-String "draws=|PRESENT|GFX-CALLBACK" | Select-Object -First 100

# Analyze results
Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

$content = Get-Content "test_unblock_output.log" -ErrorAction SilentlyContinue
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
            Write-Host "`n[FAIL] All draws are zero" -ForegroundColor Red
        }
    }
    
    $presentLines = $content | Select-String "PRESENT"
    Write-Host "`nPresent calls: $($presentLines.Count)" -ForegroundColor Yellow
    
    $callbackLines = $content | Select-String "GFX-CALLBACK"
    Write-Host "Graphics callbacks: $($callbackLines.Count)" -ForegroundColor Yellow
}

