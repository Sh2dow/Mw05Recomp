#!/usr/bin/env pwsh
# Test ring buffer write detection

$env:MW05_PM4_TRACE = "1"
$env:MW05_TRACE_RB_WRITES = "1"
$env:MW05_TRACE_KERNEL = "1"

Write-Host "Starting MW05 with ring buffer write tracing..." -ForegroundColor Green
Write-Host "Will run for 60 seconds..." -ForegroundColor Yellow

# Start the game
$proc = Start-Process -FilePath ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe" -PassThru

# Wait for 60 seconds
Start-Sleep -Seconds 60

# Kill the process
if (!$proc.HasExited) {
    Write-Host "Stopping game..." -ForegroundColor Yellow
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host "Done. Checking logs..." -ForegroundColor Green

# Check for ring buffer writes
$rbWrites = Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "HOST.RB.write" | Select-Object -Last 30
if ($rbWrites) {
    Write-Host "Found $($rbWrites.Count) ring buffer writes (showing last 30):" -ForegroundColor Green
    $rbWrites | ForEach-Object { Write-Host $_.Line }
} else {
    Write-Host "No ring buffer writes found!" -ForegroundColor Red
}

# Check for PM4 scans
$pm4Scans = Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "HOST.PM4.Scan" | Select-Object -Last 30
if ($pm4Scans) {
    Write-Host "`nFound $($pm4Scans.Count) PM4 scans (showing last 30):" -ForegroundColor Green
    $pm4Scans | ForEach-Object { Write-Host $_.Line }
} else {
    Write-Host "`nNo PM4 scans found!" -ForegroundColor Yellow
}

# Check for PM4 draw commands
$pm4Draws = Select-String -Path ".\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -Pattern "HOST.PM4.DRAW" | Select-Object -Last 30
if ($pm4Draws) {
    Write-Host "`nFound $($pm4Draws.Count) PM4 draw commands (showing last 30):" -ForegroundColor Green
    $pm4Draws | ForEach-Object { Write-Host $_.Line }
} else {
    Write-Host "`nNo PM4 draw commands found!" -ForegroundColor Yellow
}

