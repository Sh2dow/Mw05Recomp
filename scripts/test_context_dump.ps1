$env:MW05_DUMP_CONTEXT_40009D2C = "1"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Run for 10 seconds
$job = Start-Job -ScriptBlock {
    & "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" 2>&1
}

Start-Sleep -Seconds 10
Stop-Job $job
$output = Receive-Job $job
Remove-Job $job

# Kill any remaining instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

# Show relevant output
$output | Select-String "CONTEXT_DUMP|NULL-CALL" | Select-Object -First 30

