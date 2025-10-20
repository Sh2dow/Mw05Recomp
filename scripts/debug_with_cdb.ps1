# Debug with CDB (Console Debugger)
$env:MW05_XEX_PATH = "D:/Games/Xbox360/NFS Most Wanted/default.xex"

$exePath = "D:/Repos/Games/Mw05Recomp/out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe"
$dumpPath = "D:/Repos/Games/Mw05Recomp/traces/crash_dump.txt"

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force

# Find cdb.exe
$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
if (-not (Test-Path $cdbPath)) {
    Write-Host "CDB not found at $cdbPath" -ForegroundColor Red
    Write-Host "Trying to find it..." -ForegroundColor Yellow
    $cdbPath = Get-ChildItem "C:\Program Files (x86)\Windows Kits" -Recurse -Filter "cdb.exe" -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*x64*" } | Select-Object -First 1 -ExpandProperty FullName
    if (-not $cdbPath) {
        Write-Host "CDB not found. Please install Windows SDK." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Using CDB: $cdbPath" -ForegroundColor Green

# CDB commands:
# sxe av - break on access violation
# sxe ch - break on invalid handle
# sxe eh - break on C++ exception
# g - go (run until crash)
# .ecxr - display exception context
# k - stack trace
# r - registers
# q - quit
$cdbCommands = @"
.logopen $dumpPath
sxe av
sxe ch
sxe eh
sxe ld
g
.echo ===== EXCEPTION OCCURRED =====
.ecxr
.echo ===== STACK TRACE =====
k 100
.echo ===== REGISTERS =====
r
.echo ===== EXCEPTION RECORD =====
.exr -1
.echo ===== CONTEXT =====
.cxr
.echo ===== DONE =====
q
"@

$cdbCommands | Out-File -FilePath "traces/cdb_commands.txt" -Encoding ASCII

Write-Host "Starting game under debugger..." -ForegroundColor Green
Write-Host "Dump will be saved to: $dumpPath" -ForegroundColor Cyan

& $cdbPath -g -G -c "`$`$<traces/cdb_commands.txt" $exePath

Write-Host "`nDebugger finished. Analyzing dump..." -ForegroundColor Green
Get-Content $dumpPath | Select-Object -Last 100

