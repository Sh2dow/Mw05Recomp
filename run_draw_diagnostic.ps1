# Run MW05 with draw diagnostic tracing enabled
# This will log all candidate draw functions to help identify the actual draw calls

$env:MW05_DRAW_DIAGNOSTIC = "1"
$env:MW05_TRACE_KERNEL = "1"

Write-Host "Starting MW05 with draw diagnostic tracing..." -ForegroundColor Green
Write-Host "Log file: .\out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

