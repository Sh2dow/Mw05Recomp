# Analyze what the game is waiting for
$ErrorActionPreference = "Continue"

Write-Host "=== ANALYZING GAME BLOCKING BEHAVIOR ===" -ForegroundColor Cyan

if (-not (Test-Path "debug_stderr_long.txt")) {
    Write-Host "ERROR: debug_stderr_long.txt not found. Run test_longer_run.ps1 first." -ForegroundColor Red
    exit 1
}

$stderr = Get-Content "debug_stderr_long.txt"

Write-Host "`n=== THREAD CREATION ===" -ForegroundColor Yellow
$threadCreations = $stderr | Select-String "ExCreateThread returned|SYSTEM-THREAD.*started"
Write-Host "Total threads created: $($threadCreations.Count)"
$threadCreations | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== WAIT OPERATIONS ===" -ForegroundColor Yellow
$waits = $stderr | Select-String "NtWaitForSingleObjectEx|KeWaitForSingleObject"
Write-Host "Total wait operations: $($waits.Count)"
$waits | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== SLEEP OPERATIONS ===" -ForegroundColor Yellow
$sleeps = $stderr | Select-String "KeDelayExecutionThread"
Write-Host "Total sleep operations: $($sleeps.Count)"
$sleeps | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== FILE I/O ===" -ForegroundColor Yellow
$fileOps = $stderr | Select-String "NtCreateFile|NtOpenFile|NtReadFile|NtWriteFile"
Write-Host "Total file I/O operations: $($fileOps.Count)"
if ($fileOps.Count -gt 0) {
    $fileOps | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "  NO FILE I/O DETECTED!" -ForegroundColor Red
}

Write-Host "`n=== MEMORY ALLOCATIONS ===" -ForegroundColor Yellow
$memAllocs = $stderr | Select-String "MmAllocatePhysicalMemory|NtAllocateVirtualMemory"
Write-Host "Total memory allocations: $($memAllocs.Count)"
$memAllocs | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== GRAPHICS INITIALIZATION ===" -ForegroundColor Yellow
$gfxInit = $stderr | Select-String "VdInitializeEngines|VdSetGraphicsInterruptCallback|VdSwap"
Write-Host "Total graphics calls: $($gfxInit.Count)"
if ($gfxInit.Count -gt 0) {
    $gfxInit | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "  NO GRAPHICS INITIALIZATION DETECTED!" -ForegroundColor Red
}

Write-Host "`n=== VBLANK STATUS ===" -ForegroundColor Yellow
$vblank = $stderr | Select-String "VBLANK-ISR-STATUS"
$vblank | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== ERRORS AND STUBS ===" -ForegroundColor Yellow
$errors = $stderr | Select-String "ERROR|STUB|NOT IMPLEMENTED|FATAL"
Write-Host "Total errors/stubs: $($errors.Count)"
$errors | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }

Write-Host "`n=== LAST 30 LINES ===" -ForegroundColor Yellow
$stderr | Select-Object -Last 30 | ForEach-Object { Write-Host "  $_" }

Write-Host "`n=== ANALYSIS SUMMARY ===" -ForegroundColor Cyan
Write-Host "Threads created: $($threadCreations.Count)"
Write-Host "Wait operations: $($waits.Count)"
Write-Host "Sleep operations: $($sleeps.Count)"
Write-Host "File I/O operations: $($fileOps.Count)"
Write-Host "Memory allocations: $($memAllocs.Count)"
Write-Host "Graphics calls: $($gfxInit.Count)"

if ($gfxInit.Count -eq 0) {
    Write-Host "`nCRITICAL: Game never initialized graphics!" -ForegroundColor Red
    Write-Host "The game is stuck before VdSetGraphicsInterruptCallback is called." -ForegroundColor Red
}

if ($fileOps.Count -eq 0) {
    Write-Host "`nCRITICAL: Game never performed any file I/O!" -ForegroundColor Red
    Write-Host "The game may be waiting for file system initialization." -ForegroundColor Red
}

if ($threadCreations.Count -le 6) {
    Write-Host "`nWARNING: Only $($threadCreations.Count) threads created (expected 9+)" -ForegroundColor Yellow
    Write-Host "The game may be waiting for additional threads to be created." -ForegroundColor Yellow
}

# Check for specific blocking patterns
Write-Host "`n=== CHECKING FOR BLOCKING PATTERNS ===" -ForegroundColor Cyan

# Pattern 1: Waiting on a specific handle repeatedly
$waitHandles = $stderr | Select-String "NtWaitForSingleObjectEx.*Handle=0x([0-9A-F]+)" | ForEach-Object {
    if ($_ -match "Handle=0x([0-9A-F]+)") {
        $matches[1]
    }
}
if ($waitHandles) {
    $handleGroups = $waitHandles | Group-Object | Sort-Object Count -Descending
    Write-Host "Most frequently waited handles:"
    $handleGroups | Select-Object -First 5 | ForEach-Object {
        Write-Host "  Handle 0x$($_.Name): $($_.Count) waits"
    }
}

# Pattern 2: Check if main thread is stuck
$mainThreadWaits = $stderr | Select-String "KeWaitForSingleObject|NtWaitForSingleObjectEx" | Select-Object -Last 10
if ($mainThreadWaits) {
    Write-Host "`nLast 10 wait operations:"
    $mainThreadWaits | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`nAnalysis complete." -ForegroundColor Cyan

