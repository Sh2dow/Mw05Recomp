# Test script for Release build
# This script builds the Release configuration and runs a quick test

param(
    [int]$Duration = 30,  # Test duration in seconds
    [switch]$SkipBuild    # Skip build step if already built
)

$ErrorActionPreference = "Stop"

Write-Host "=== MW05 Release Build Test ===" -ForegroundColor Cyan
Write-Host ""

# Get repository root (handle both direct execution and script invocation)
if ($PSScriptRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
} else {
    $RepoRoot = Get-Location
}

# Verify we're in the right directory
if (-not (Test-Path "$RepoRoot\CMakePresets.json")) {
    Write-Host "ERROR: Not in repository root! Looking for CMakePresets.json" -ForegroundColor Red
    Write-Host "Current location: $RepoRoot" -ForegroundColor Yellow
    exit 1
}

Set-Location $RepoRoot
Write-Host "Repository root: $RepoRoot" -ForegroundColor Cyan
Write-Host ""

# Build Release configuration
if (-not $SkipBuild) {
    Write-Host "[1/3] Configuring Release build..." -ForegroundColor Yellow
    cmake --preset x64-Clang-Release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: CMake configuration failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[2/3] Building Release configuration..." -ForegroundColor Yellow
    cmake --build out/build/x64-Clang-Release --target Mw05Recomp -j
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[SKIP] Skipping build step (using existing build)" -ForegroundColor Yellow
}

Write-Host "[3/3] Testing Release build..." -ForegroundColor Yellow
Write-Host ""

# Kill any existing instances
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# Path to Release executable
$ExePath = "out\build\x64-Clang-Release\Mw05Recomp\Mw05Recomp.exe"

if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: Release executable not found at: $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "Executable: $ExePath" -ForegroundColor Cyan
Write-Host "Test duration: $Duration seconds" -ForegroundColor Cyan
Write-Host ""

# Create output directory for logs
$LogDir = "traces"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$StdoutLog = "$LogDir\release_test_stdout_$Timestamp.txt"
$StderrLog = "$LogDir\release_test_stderr_$Timestamp.txt"

Write-Host "Starting Release build test..." -ForegroundColor Green
Write-Host "Logs will be saved to:" -ForegroundColor Cyan
Write-Host "  stdout: $StdoutLog" -ForegroundColor Gray
Write-Host "  stderr: $StderrLog" -ForegroundColor Gray
Write-Host ""

# Start the process
$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = $ExePath
$ProcessInfo.WorkingDirectory = $RepoRoot
$ProcessInfo.UseShellExecute = $false
$ProcessInfo.RedirectStandardOutput = $true
$ProcessInfo.RedirectStandardError = $true
$ProcessInfo.CreateNoWindow = $false

$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $ProcessInfo

# Event handlers for output
$StdoutBuilder = New-Object System.Text.StringBuilder
$StderrBuilder = New-Object System.Text.StringBuilder

$StdoutEvent = Register-ObjectEvent -InputObject $Process -EventName OutputDataReceived -Action {
    if ($EventArgs.Data) {
        [void]$Event.MessageData.AppendLine($EventArgs.Data)
        Write-Host $EventArgs.Data -ForegroundColor Gray
    }
} -MessageData $StdoutBuilder

$StderrEvent = Register-ObjectEvent -InputObject $Process -EventName ErrorDataReceived -Action {
    if ($EventArgs.Data) {
        [void]$Event.MessageData.AppendLine($EventArgs.Data)
        Write-Host $EventArgs.Data -ForegroundColor Yellow
    }
} -MessageData $StderrBuilder

# Start process
$Process.Start() | Out-Null
$Process.BeginOutputReadLine()
$Process.BeginErrorReadLine()

Write-Host "Process started (PID: $($Process.Id))" -ForegroundColor Green
Write-Host "Waiting $Duration seconds..." -ForegroundColor Cyan
Write-Host ""

# Wait for specified duration
$StartTime = Get-Date
$EndTime = $StartTime.AddSeconds($Duration)

while ((Get-Date) -lt $EndTime) {
    if ($Process.HasExited) {
        Write-Host "WARNING: Process exited early!" -ForegroundColor Red
        break
    }
    Start-Sleep -Milliseconds 500
}

$Elapsed = ((Get-Date) - $StartTime).TotalSeconds

# Stop process if still running
if (-not $Process.HasExited) {
    Write-Host "Stopping process..." -ForegroundColor Yellow
    $Process.Kill()
    $Process.WaitForExit(5000)
}

# Cleanup event handlers
Unregister-Event -SourceIdentifier $StdoutEvent.Name
Unregister-Event -SourceIdentifier $StderrEvent.Name
Remove-Job -Name $StdoutEvent.Name -Force
Remove-Job -Name $StderrEvent.Name -Force

# Save logs
$StdoutBuilder.ToString() | Out-File -FilePath $StdoutLog -Encoding UTF8
$StderrBuilder.ToString() | Out-File -FilePath $StderrLog -Encoding UTF8

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host "Elapsed time: $([math]::Round($Elapsed, 2)) seconds" -ForegroundColor Cyan
Write-Host ""

# Analyze results
$StderrText = $StderrBuilder.ToString()

# Check for critical errors
$HasCrash = $StderrText -match "Exception|Assertion|CRASH|FATAL"
$HasHeapCorruption = $StderrText -match "o1heap|heap corruption"
$HasVBlank = $StderrText -match "VBLANK|VBlank"
$HasPM4 = $StderrText -match "PM4"
$HasThreads = $StderrText -match "Thread|THREAD"

Write-Host "Analysis:" -ForegroundColor Cyan
Write-Host "  Crash detected: $(if ($HasCrash) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($HasCrash) { 'Red' } else { 'Green' })
Write-Host "  Heap corruption: $(if ($HasHeapCorruption) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($HasHeapCorruption) { 'Red' } else { 'Green' })
Write-Host "  VBlank activity: $(if ($HasVBlank) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($HasVBlank) { 'Green' } else { 'Yellow' })
Write-Host "  PM4 processing: $(if ($HasPM4) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($HasPM4) { 'Green' } else { 'Yellow' })
Write-Host "  Thread activity: $(if ($HasThreads) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($HasThreads) { 'Green' } else { 'Yellow' })
Write-Host ""

if ($HasCrash -or $HasHeapCorruption) {
    Write-Host "RESULT: FAILED - Critical errors detected" -ForegroundColor Red
    exit 1
} elseif (-not $HasVBlank -and -not $HasPM4) {
    Write-Host "RESULT: UNCERTAIN - No activity detected (may be hanging)" -ForegroundColor Yellow
    exit 2
} else {
    Write-Host "RESULT: SUCCESS - Release build appears to be working!" -ForegroundColor Green
    exit 0
}

