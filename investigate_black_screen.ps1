# Investigate Black Screen Issue
# Run the game and monitor for graphics-related activity

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "BLACK SCREEN INVESTIGATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will run the game and monitor:" -ForegroundColor Yellow
Write-Host "  1. VdSwap() calls (present/buffer swap)" -ForegroundColor Yellow
Write-Host "  2. Natural callback registration" -ForegroundColor Yellow
Write-Host "  3. GPU command buffer activity" -ForegroundColor Yellow
Write-Host "  4. Video mode configuration" -ForegroundColor Yellow
Write-Host ""
Write-Host "The game will run for 60 seconds, then we'll analyze the logs." -ForegroundColor Yellow
Write-Host ""

# No forced callback registration - let the game run naturally
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB -ErrorAction SilentlyContinue
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB_CTX -ErrorAction SilentlyContinue
Remove-Item Env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS -ErrorAction SilentlyContinue
Remove-Item Env:MW05_GFX_CALLBACK_FREQUENCY -ErrorAction SilentlyContinue
Remove-Item Env:MW05_GFX_CALLBACK_MAX_INVOCATIONS -ErrorAction SilentlyContinue
Remove-Item Env:MW05_DISABLE_CALLBACK_INVOCATION -ErrorAction SilentlyContinue

Write-Host "Starting game..." -ForegroundColor Green

# Run for 60 seconds
$process = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru -NoNewWindow

Write-Host "Game running (PID: $($process.Id))" -ForegroundColor Green
Write-Host "Waiting 60 seconds..." -ForegroundColor Yellow

Start-Sleep -Seconds 60

Write-Host "`nStopping game..." -ForegroundColor Yellow
Stop-Process -Id $process.Id -Force

Write-Host "`nGame stopped. Analyzing logs..." -ForegroundColor Green
Write-Host ""

# Check if log file exists
$logFile = ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log"
if (Test-Path $logFile) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "LOG ANALYSIS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $content = Get-Content $logFile
    
    # Check for VdSwap calls
    $swapCalls = $content | Select-String "VdSwap"
    Write-Host "`nVdSwap() calls: $($swapCalls.Count)" -ForegroundColor $(if ($swapCalls.Count -gt 0) { "Green" } else { "Red" })
    if ($swapCalls.Count -gt 0) {
        Write-Host "First 5 VdSwap calls:" -ForegroundColor Yellow
        $swapCalls | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  [X] NO VdSwap calls found! Game is not presenting frames." -ForegroundColor Red
    }
    
    # Check for natural callback registration
    $naturalReg = $content | Select-String "NATURAL-REG"
    Write-Host "`nNatural callback registration: $($naturalReg.Count)" -ForegroundColor $(if ($naturalReg.Count -gt 0) { "Green" } else { "Yellow" })
    if ($naturalReg.Count -gt 0) {
        Write-Host "Callback registration details:" -ForegroundColor Yellow
        $naturalReg | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  [i] Game did not naturally register a graphics callback" -ForegroundColor Yellow
    }
    
    # Check for video mode setup
    $videoMode = $content | Select-String "VdSetDisplayMode|VdQueryVideoMode"
    Write-Host "`nVideo mode calls: $($videoMode.Count)" -ForegroundColor $(if ($videoMode.Count -gt 0) { "Green" } else { "Yellow" })
    if ($videoMode.Count -gt 0) {
        Write-Host "First 5 video mode calls:" -ForegroundColor Yellow
        $videoMode | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
    }
    
    # Check for GPU command buffer activity
    $gpuCommands = $content | Select-String "VdSetSystemCommandBuffer|VdQuerySystemCommandBuffer"
    Write-Host "`nGPU command buffer calls: $($gpuCommands.Count)" -ForegroundColor $(if ($gpuCommands.Count -gt 0) { "Green" } else { "Yellow" })
    if ($gpuCommands.Count -gt 0) {
        Write-Host "First 5 GPU command buffer calls:" -ForegroundColor Yellow
        $gpuCommands | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
    }
    
    # Check for render target setup
    $renderTargets = $content | Select-String "SetRenderTarget|CreateRenderTarget"
    Write-Host "`nRender target calls: $($renderTargets.Count)" -ForegroundColor $(if ($renderTargets.Count -gt 0) { "Green" } else { "Yellow" })
    
    # Check for draw calls
    $drawCalls = $content | Select-String "Draw|DrawIndexed"
    Write-Host "`nDraw calls: $($drawCalls.Count)" -ForegroundColor $(if ($drawCalls.Count -gt 0) { "Green" } else { "Red" })
    if ($drawCalls.Count -eq 0) {
        Write-Host "  [X] NO draw calls found! Game is not submitting geometry." -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($swapCalls.Count -eq 0) {
        Write-Host "[X] PRIMARY ISSUE: No VdSwap calls" -ForegroundColor Red
        Write-Host "   The game is NOT presenting frames to the screen." -ForegroundColor Red
        Write-Host "   This is likely why the screen is black." -ForegroundColor Red
    }

    if ($drawCalls.Count -eq 0) {
        Write-Host "[X] SECONDARY ISSUE: No draw calls" -ForegroundColor Red
        Write-Host "   The game is NOT submitting geometry to the GPU." -ForegroundColor Red
    }

    if ($swapCalls.Count -gt 0 -and $drawCalls.Count -gt 0) {
        Write-Host "[OK] Game is presenting frames and drawing geometry" -ForegroundColor Green
        Write-Host "   The black screen issue might be elsewhere." -ForegroundColor Green
    }

} else {
    Write-Host "[X] Log file not found: $logFile" -ForegroundColor Red
}

Write-Host ""
Write-Host "Investigation complete!" -ForegroundColor Green

