# Kill any running instances
Get-Process Mw05Recomp -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Set environment variables for PM4 tracing
$env:MW05_PM4_TRACE = "1"
$env:MW05_PM4_TRACE_REGS = "1"
$env:MW05_PM4_TRACE_REG_BUDGET = "200"

# Run for 5 seconds and capture output
$job = Start-Job -ScriptBlock {
    & "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" 2>&1
}

Start-Sleep -Seconds 5

# Kill the process
Get-Process Mw05Recomp -ErrorAction SilentlyContinue | Stop-Process -Force

# Wait for job to finish
Wait-Job $job -Timeout 2 | Out-Null

# Get output
$output = Receive-Job $job
Remove-Job $job -Force

# Save to file
$output | Select-Object -First 500 | Out-File -FilePath "Traces/pm4_trace_sample.txt"

Write-Host "PM4 trace saved to Traces/pm4_trace_sample.txt"
Write-Host "Lines captured: $(($output | Measure-Object).Count)"

