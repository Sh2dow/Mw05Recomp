# Setup script for LLVM environment
# This script helps set up LLVM_HOME for building MW05Recomp with Clang

param(
    [string]$LLVMPath = "",
    [switch]$Persistent,  # Set environment variable persistently
    [switch]$Download     # Download and install LLVM
)

Write-Host "=== MW05Recomp LLVM Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check if LLVM_HOME is already set
$CurrentLLVMHome = [Environment]::GetEnvironmentVariable('LLVM_HOME', 'User')
if ($CurrentLLVMHome) {
    Write-Host "LLVM_HOME is currently set to: $CurrentLLVMHome" -ForegroundColor Yellow
    if (Test-Path "$CurrentLLVMHome\bin\clang-cl.exe") {
        Write-Host "  clang-cl.exe found: VALID" -ForegroundColor Green
    } else {
        Write-Host "  clang-cl.exe NOT found: INVALID" -ForegroundColor Red
    }
    Write-Host ""
}

# If download requested
if ($Download) {
    Write-Host "Opening LLVM download page..." -ForegroundColor Cyan
    Start-Process "https://github.com/llvm/llvm-project/releases/latest"
    Write-Host ""
    Write-Host "Please download and install LLVM for Windows (LLVM-*-win64.exe)" -ForegroundColor Yellow
    Write-Host "Recommended installation path: C:\Program Files\LLVM" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After installation, run this script again with the installation path:" -ForegroundColor Yellow
    Write-Host "  .\scripts\setup_llvm.ps1 -LLVMPath 'C:\Program Files\LLVM' -Persistent" -ForegroundColor Cyan
    exit 0
}

# Auto-detect LLVM installations
$DetectedPaths = @()

$SearchPaths = @(
    "C:\Program Files\LLVM",
    "C:\LLVM",
    "D:\LLVM",
    "C:\Program Files (x86)\LLVM"
)

foreach ($Path in $SearchPaths) {
    if (Test-Path "$Path\bin\clang-cl.exe") {
        $DetectedPaths += $Path
    }
}

if ($DetectedPaths.Count -gt 0) {
    Write-Host "Detected LLVM installations:" -ForegroundColor Green
    for ($i = 0; $i -lt $DetectedPaths.Count; $i++) {
        Write-Host "  [$($i+1)] $($DetectedPaths[$i])" -ForegroundColor Cyan
    }
    Write-Host ""
}

# If path not provided, prompt user
if (-not $LLVMPath) {
    if ($DetectedPaths.Count -eq 1) {
        $LLVMPath = $DetectedPaths[0]
        Write-Host "Using detected LLVM installation: $LLVMPath" -ForegroundColor Green
    } elseif ($DetectedPaths.Count -gt 1) {
        Write-Host "Multiple LLVM installations detected. Please specify which one to use:" -ForegroundColor Yellow
        Write-Host "  .\scripts\setup_llvm.ps1 -LLVMPath '<path>' -Persistent" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Or download LLVM:" -ForegroundColor Yellow
        Write-Host "  .\scripts\setup_llvm.ps1 -Download" -ForegroundColor Cyan
        exit 1
    } else {
        Write-Host "No LLVM installation detected." -ForegroundColor Red
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  1. Download and install LLVM:" -ForegroundColor Cyan
        Write-Host "     .\scripts\setup_llvm.ps1 -Download" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  2. Specify existing LLVM installation:" -ForegroundColor Cyan
        Write-Host "     .\scripts\setup_llvm.ps1 -LLVMPath '<path>' -Persistent" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  3. Use MSVC instead of Clang (no LLVM needed):" -ForegroundColor Cyan
        Write-Host "     cmake --preset x64-MSVC-v141-Release" -ForegroundColor Gray
        exit 1
    }
}

# Validate path
if (-not (Test-Path "$LLVMPath\bin\clang-cl.exe")) {
    Write-Host "ERROR: clang-cl.exe not found at: $LLVMPath\bin\clang-cl.exe" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please verify the LLVM installation path and try again." -ForegroundColor Yellow
    exit 1
}

# Get LLVM version
$ClangVersion = & "$LLVMPath\bin\clang-cl.exe" --version 2>&1 | Select-Object -First 1
Write-Host "Found LLVM: $ClangVersion" -ForegroundColor Green
Write-Host ""

# Set environment variable
if ($Persistent) {
    Write-Host "Setting LLVM_HOME persistently (User environment variable)..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable('LLVM_HOME', $LLVMPath, 'User')
    Write-Host "LLVM_HOME set to: $LLVMPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "NOTE: You may need to restart your terminal/IDE for the change to take effect." -ForegroundColor Yellow
} else {
    Write-Host "Setting LLVM_HOME for current session only..." -ForegroundColor Yellow
    $env:LLVM_HOME = $LLVMPath
    Write-Host "LLVM_HOME set to: $LLVMPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "NOTE: This is temporary. Use -Persistent flag to set permanently:" -ForegroundColor Yellow
    Write-Host "  .\scripts\setup_llvm.ps1 -LLVMPath '$LLVMPath' -Persistent" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "You can now build with Clang:" -ForegroundColor Cyan
Write-Host "  cmake --preset x64-Clang-Release" -ForegroundColor Gray
Write-Host "  cmake --build out/build/x64-Clang-Release" -ForegroundColor Gray
Write-Host ""

