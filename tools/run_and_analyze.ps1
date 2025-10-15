#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run MW05 and perform comprehensive trace analysis to identify blocking points.

.DESCRIPTION
    This script:
    1. Kills any running MW05 instances
    2. Clears old trace logs
    3. Runs MW05 for a specified duration
    4. Analyzes the trace log to identify blocking points
    5. Generates diagnostic reports

.PARAMETER Duration
    How long to run the game (in seconds). Default: 30

.PARAMETER SkipBuild
    Skip rebuilding the application. Default: false

.EXAMPLE
    ./tools/run_and_analyze.ps1 -Duration 60
    ./tools/run_and_analyze.ps1 -SkipBuild
#>

param(
    [int]$Duration = 30,
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Header($msg) {
    Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host $('=' * 80) -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Write-Info($msg) {
    Write-Host "[*] $msg" -ForegroundColor Yellow
}

function Write-Error($msg) {
    Write-Host "[!] $msg" -ForegroundColor Red
}

# Paths
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildDir = Join-Path $RepoRoot "out\build\x64-Clang-Debug\Mw05Recomp"
$ExePath = Join-Path $BuildDir "Mw05Recomp.exe"
$TraceLog = Join-Path $BuildDir "mw05_host_trace.log"
$StderrLog = Join-Path $BuildDir "debug_stderr.txt"
$AnalysisReport = Join-Path $BuildDir "trace_analysis_report.json"
$CallTreeReport = Join-Path $BuildDir "audio_registration_call_tree.json"

Write-Header "MW05 Diagnostic Runner and Analyzer"

# Step 1: Kill any running instances
Write-Info "Killing any running MW05 instances..."
Get-Process -Name "Mw05Recomp" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# Step 2: Build if needed
if (-not $SkipBuild) {
    Write-Header "Building Application"
    Push-Location $RepoRoot
    try {
        & ./build_cmd.ps1 -Stage app
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed with exit code $LASTEXITCODE"
            exit 1
        }
        Write-Success "Build completed successfully"
    }
    finally {
        Pop-Location
    }
}
else {
    Write-Info "Skipping build (using existing binary)"
}

# Step 3: Verify executable exists
if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found: $ExePath"
    exit 1
}

# Step 4: Clear old logs
Write-Info "Clearing old trace logs..."
if (Test-Path $TraceLog) {
    Remove-Item $TraceLog -Force
}
if (Test-Path $StderrLog) {
    Remove-Item $StderrLog -Force
}
if (Test-Path $AnalysisReport) {
    Remove-Item $AnalysisReport -Force
}
if (Test-Path $CallTreeReport) {
    Remove-Item $CallTreeReport -Force
}

# Step 5: Run the game
Write-Header "Running MW05 for $Duration seconds"
Write-Info "Executable: $ExePath"
Write-Info "Trace log: $TraceLog"
Write-Info "Stderr log: $StderrLog"

$process = Start-Process -FilePath $ExePath `
    -WorkingDirectory $BuildDir `
    -RedirectStandardError $StderrLog `
    -PassThru `
    -WindowStyle Normal

Write-Success "Process started (PID: $($process.Id))"
Write-Info "Waiting $Duration seconds..."

# Wait for specified duration
Start-Sleep -Seconds $Duration

# Kill the process
Write-Info "Stopping process..."
if (-not $process.HasExited) {
    $process.Kill()
    $process.WaitForExit(5000)
}

Write-Success "Process stopped"

# Step 6: Check if trace log was created
if (-not (Test-Path $TraceLog)) {
    Write-Error "Trace log was not created: $TraceLog"
    Write-Info "Check stderr log for errors: $StderrLog"
    exit 1
}

$traceSize = (Get-Item $TraceLog).Length
Write-Success "Trace log created: $([math]::Round($traceSize / 1MB, 2)) MB"

# Step 7: Run trace analyzer
Write-Header "Analyzing Trace Log"
Push-Location $RepoRoot
try {
    python tools/trace_analyzer.py $TraceLog
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Trace analysis failed"
        exit 1
    }
}
finally {
    Pop-Location
}

# Step 8: Run function tracer
Write-Header "Analyzing Function Call Chains"
Push-Location $RepoRoot
try {
    python tools/function_tracer.py
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Function tracer failed"
        exit 1
    }
}
finally {
    Pop-Location
}

# Step 9: Display summary
Write-Header "Analysis Summary"

if (Test-Path $AnalysisReport) {
    $report = Get-Content $AnalysisReport | ConvertFrom-Json
    
    Write-Info "Total kernel calls: $($report.summary.total_kernel_calls)"
    Write-Info "Unique kernel functions: $($report.summary.unique_kernel_functions)"
    Write-Info "Total stub calls: $($report.summary.total_stub_calls)"
    Write-Info "Unique stubs: $($report.summary.unique_stubs)"
    
    Write-Host "`nBlocking Indicators:" -ForegroundColor Yellow
    Write-Host "  Sleep calls: $($report.blocking_indicators.sleep_calls)" -ForegroundColor $(if ($report.blocking_indicators.sleep_calls -gt 1000) { "Red" } else { "Green" })
    Write-Host "  Wait calls: $($report.blocking_indicators.wait_calls)" -ForegroundColor $(if ($report.blocking_indicators.wait_calls -gt 1000) { "Red" } else { "Green" })
    Write-Host "  Signal calls: $($report.blocking_indicators.signal_calls)" -ForegroundColor $(if ($report.blocking_indicators.signal_calls -eq 0) { "Red" } else { "Green" })
    Write-Host "  Audio registration: $($report.blocking_indicators.audio_registration)" -ForegroundColor $(if ($report.blocking_indicators.audio_registration -eq 0) { "Red" } else { "Green" })
    Write-Host "  File I/O: $($report.blocking_indicators.file_io)" -ForegroundColor $(if ($report.blocking_indicators.file_io -eq 0) { "Red" } else { "Green" })
    
    Write-Success "Analysis report: $AnalysisReport"
}
else {
    Write-Error "Analysis report not found: $AnalysisReport"
}

if (Test-Path $CallTreeReport) {
    Write-Success "Call tree report: $CallTreeReport"
}

# Step 10: Check stderr for errors
Write-Header "Checking Stderr for Errors"
if (Test-Path $StderrLog) {
    $stderrContent = Get-Content $StderrLog -Raw
    
    # Count error patterns
    $stubCount = ([regex]::Matches($stderrContent, "STUB:")).Count
    $notImplCount = ([regex]::Matches($stderrContent, "NOT IMPLEMENTED")).Count
    $errorCount = ([regex]::Matches($stderrContent, "ERROR|FATAL|CRASH")).Count
    
    Write-Info "STUB calls in stderr: $stubCount"
    Write-Info "NOT IMPLEMENTED calls in stderr: $notImplCount"
    Write-Info "ERROR/FATAL/CRASH messages: $errorCount"
    
    if ($errorCount -gt 0) {
        Write-Error "Found $errorCount error messages in stderr"
        Write-Info "Check stderr log: $StderrLog"
    }
}

Write-Header "Diagnostic Analysis Complete!"
Write-Info "Next steps:"
Write-Info "1. Review the analysis report: $AnalysisReport"
Write-Info "2. Review the call tree report: $CallTreeReport"
Write-Info "3. Check the trace log for patterns: $TraceLog"
Write-Info "4. Check stderr for errors: $StderrLog"

exit 0

