param(
  [string]$Dir = "D:\Repos\Games\Mw05Recomp\out\build\x64-Clang-Debug\Mw05Recomp",
  [int]$Tail = 200
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path $Dir)) { throw "Dir not found: $Dir" }
$logs = Get-ChildItem -Path $Dir -Filter *.log | Sort-Object LastWriteTime -Descending
foreach ($l in $logs | Select-Object -First 3) {
  Write-Host ("[LOG] {0} {1}" -f $l.FullName, $l.LastWriteTime)
}
$latest = $logs | Select-Object -First 1
if ($latest) {
  Write-Host ("[TAIL] {0}" -f $latest.FullName)
  Get-Content -Path $latest.FullName -Tail $Tail
} else {
  Write-Host "[LOG] No .log files in $Dir"
}

