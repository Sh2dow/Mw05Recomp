$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "450"  # Delay until after the crash point
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"  # 0 = unlimited

Write-Host "Testing with callback registration delayed to tick 450 (after crash point)"
Write-Host "This will test if the crash is related to callback registration timing"
Write-Host ""

$timeout = 20
$exe = ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

$proc = Start-Process -FilePath $exe -PassThru -NoNewWindow
Start-Sleep -Seconds $timeout
if (!$proc.HasExited) {
    Write-Host "Stopping process after $timeout seconds..."
    $proc.Kill()
    $proc.WaitForExit()
}

Write-Host ""
Write-Host "Exit code: $($proc.ExitCode)"

