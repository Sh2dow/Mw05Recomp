# Validate environment variables against run_with_debug.ps1

Write-Host "=== Environment Variable Validation ===" -ForegroundColor Cyan
Write-Host ""

# Critical variables that MUST be correct
$critical_vars = @{
    "MW05_RENDER_THREAD_CTX" = "0x40009D2C"  # MUST be this value (from Xenia)
    "MW05_RENDER_THREAD_ENTRY" = "0x825AA970"  # Render thread entry point
    "MW05_FORCE_RENDER_THREAD" = "1"  # Must force render thread creation
}

# Check critical variables
$has_errors = $false
foreach ($var in $critical_vars.Keys) {
    $expected = $critical_vars[$var]
    $actual = [Environment]::GetEnvironmentVariable($var, "User")
    
    if ($actual -eq $expected) {
        Write-Host "[OK] $var = $actual" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] $var = $actual (expected: $expected)" -ForegroundColor Red
        $has_errors = $true
    }
}

Write-Host ""

if ($has_errors) {
    Write-Host "=== ERRORS FOUND ===" -ForegroundColor Red
    Write-Host "Please update your environment variables to match the expected values." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To fix, run these commands in PowerShell (as Administrator):" -ForegroundColor Yellow
    Write-Host ""
    foreach ($var in $critical_vars.Keys) {
        $expected = $critical_vars[$var]
        Write-Host "[Environment]::SetEnvironmentVariable('$var', '$expected', 'User')" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "Then restart your terminal/IDE for changes to take effect." -ForegroundColor Yellow
} else {
    Write-Host "=== ALL CRITICAL VARIABLES ARE CORRECT ===" -ForegroundColor Green
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

