$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"  # 0 = unlimited

Write-Host "Testing with VdInitializeEDRAM + VdInitializeEngines before callback registration"
Write-Host "Callback frequency: every 10 ticks (6Hz)"
Write-Host "Max invocations: unlimited"
Write-Host ""

$timeout = 15
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

