param(
  [string]$File = "D:\Repos\Games\Mw05Recomp\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log",
  [string]$Pattern = "",
  [int]$Last = 40
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path $File)) { throw "File not found: $File" }
if ([string]::IsNullOrEmpty($Pattern)) { throw "Pattern must be provided" }
Select-String -Path $File -Pattern $Pattern | Select-Object -Last $Last | ForEach-Object { $_.Line }

