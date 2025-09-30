# Runs run_debug.ps1 to set envs and start the app, then kills it after a timeout.
param(
  [int]$Seconds = 40
)
$ErrorActionPreference = 'Stop'
# Launch run_debug.ps1 in its own PowerShell so its working directory changes don't affect us
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$repoRoot = if ($repoRoot) { (Resolve-Path $repoRoot).Path } else { (Get-Location).Path }
Write-Host "[TIMED] repoRoot=$repoRoot"
$runScript = Join-Path $repoRoot 'run_debug.ps1'
if (!(Test-Path $runScript)) { throw "run_debug.ps1 not found at $runScript" }
$psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$runScript`""
$ps = Start-Process -FilePath "powershell.exe" -ArgumentList $psArgs -WorkingDirectory $repoRoot -PassThru
Write-Host "[TIMED] Spawned PowerShell PID=$($ps.Id), waiting $Seconds s before killing Mw05Recomp.exe"
Start-Sleep -Seconds $Seconds
# Try to kill the game first, then the wrapper powershell
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
if (!$ps.HasExited) { Stop-Process -Id $ps.Id -Force -ErrorAction SilentlyContinue }
Write-Host "[TIMED] Done."
