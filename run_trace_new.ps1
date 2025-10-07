$env:MW05_TRACE_INDIRECT = "1"
$proc = Start-Process -FilePath "out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe" -NoNewWindow -PassThru -RedirectStandardError "indirect_new.txt"
Start-Sleep -Seconds 10
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Host "Checking for new indirect misses..."
if (Test-Path "indirect_new.txt") {
    $content = Get-Content "indirect_new.txt"
    if ($content) {
        Write-Host "Found indirect misses:"
        $content | Select-Object -First 50
    } else {
        Write-Host "No indirect misses found"
    }
}

