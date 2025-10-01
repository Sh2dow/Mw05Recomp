param(
  [int]$Seconds = 90,
  [string]$BuildDir = "..\out\build\x64-Clang-Debug\Mw05Recomp",
  [switch]$Rebuild = $false,
  [switch]$WithCDB = $true
)

# Resolve BuildDir relative to the caller's working directory, not the script folder
$callerCwd = Get-Location
if (-not [System.IO.Path]::IsPathRooted($BuildDir)) {
  $BuildDir = Join-Path $callerCwd.Path $BuildDir
}


$ErrorActionPreference = 'Stop'

$LogDir = (Resolve-Path $BuildDir).Path
$exe    = Join-Path $LogDir 'Mw05Recomp.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Exe not found: $exe" }

# Optional rebuild step (robust pathing regardless of caller CWD)
if ($Rebuild) {
  $buildPs1 = Join-Path $PSScriptRoot '..\build_cmd.ps1'
  if (-not (Test-Path -LiteralPath $buildPs1)) {
    throw "build_cmd.ps1 not found at $buildPs1. Run from repo or pass -Rebuild:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\\build_cmd.ps1 -Stage app -Preset x64-Clang-Debug"
  }
  Write-Host "[ENV-RUN] Rebuilding app via $buildPs1 ..."
  & powershell -NoProfile -ExecutionPolicy Bypass -File $buildPs1 -Stage app -Preset x64-Clang-Debug
}

# Thin wrapper: call run_debug.ps1 to unify behavior (redirects logs, quiet console)
# Also rate-limit UnblockThread spam by default
$env:MW05_UNBLOCK_LOG_MS  = '2000'
$env:MW05_UNBLOCK_LOG_MAX = '12'

$runDebug = Join-Path $PSScriptRoot '..\run_debug.ps1'
if (-not (Test-Path -LiteralPath $runDebug)) { throw "run_debug.ps1 not found at $runDebug" }

$msgCdb = if ($WithCDB) { 'WithCDB=$true' } else { 'WithCDB=$false' }
Write-Host "[ENV-RUN] Delegating to run_debug.ps1 ($msgCdb), timeout=$Seconds s" -ForegroundColor Cyan
$argsList = @('-TimeoutSeconds', $Seconds, '-BuildDir', $LogDir, '-CloseOnExit')
if ($WithCDB) { $argsList += '-WithCDB' } else { $argsList += '-WithCDB:$false' }
& powershell -NoProfile -ExecutionPolicy Bypass -File $runDebug @argsList

Write-Host "[ENV-RUN] Done"
