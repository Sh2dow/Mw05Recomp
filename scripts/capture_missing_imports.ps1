#!/usr/bin/env pwsh
# Capture missing imports from game execution

param(
    [int]$TimeoutSec = 10
)

Write-Host "=== CAPTURING MISSING IMPORTS ===" -ForegroundColor Cyan

# Set environment variables
$env:MW05_UNBLOCK_MAIN = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_PRESENT = "1"

Write-Host "Running game for $TimeoutSec seconds..." -ForegroundColor Yellow

# Run the game with timeout and capture output to a single file
$exe = ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"
$logOut = "missing_imports_stdout.log"
$logErr = "missing_imports_stderr.log"
if (Test-Path $logOut) { Remove-Item $logOut -Force -ErrorAction SilentlyContinue }
if (Test-Path $logErr) { Remove-Item $logErr -Force -ErrorAction SilentlyContinue }

$p = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr -WindowStyle Hidden
Start-Sleep -Seconds $TimeoutSec
if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

# Small delay to ensure file buffers flush
Start-Sleep -Milliseconds 200

# Analyze results
Write-Host "`n=== ANALYSIS ===" -ForegroundColor Cyan

$contentOut = Get-Content $logOut -ErrorAction SilentlyContinue
$contentErr = Get-Content $logErr -ErrorAction SilentlyContinue
$content = @()
if ($contentOut) { $content += $contentOut }
if ($contentErr) { $content += $contentErr }

if ($content -and $content.Length -gt 0) {
    $notImpl = $content | Select-String "NOT IMPLEMENTED"
    if ($notImpl) {
        Write-Host "`nMissing imports found: $($notImpl.Count)" -ForegroundColor Yellow

        # Get unique missing imports
        $unique = $notImpl | Sort-Object | Get-Unique
        Write-Host "`nUnique missing imports:" -ForegroundColor Green
        $unique | Select-Object -First 50

        # Count by import name
        Write-Host "`nTop missing imports:" -ForegroundColor Green
        $notImpl | ForEach-Object {
            if ($_ -match "__imp__(\w+)") {
                $matches[1]
            }
        } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 20 | ForEach-Object {
            Write-Host "  $($_.Name): $($_.Count) times"
        }
    } else {
        Write-Host "`nNo NOT IMPLEMENTED messages found!" -ForegroundColor Green
    }

    # Check for file I/O
    $fileIO = $content | Select-String "NtCreateFile|NtOpenFile|NtReadFile|NtWriteFile|NtClose"
    Write-Host "`nFile I/O calls: $($fileIO.Count)" -ForegroundColor Yellow
    if ($fileIO.Count -gt 0) {
        Write-Host "Sample file I/O calls:" -ForegroundColor Green
        $fileIO | Select-Object -First 5
    }
}

