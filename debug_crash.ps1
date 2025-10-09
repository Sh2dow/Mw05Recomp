# Debug script to help analyze the crash
# This script provides information for manual debugging

Write-Host "=== MW05 Crash Debugging Guide ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "CRASH INFORMATION:" -ForegroundColor Yellow
Write-Host "  Crash offset: +0x19DCA5" -ForegroundColor White
Write-Host "  Exception: Access Violation (0xC0000005)" -ForegroundColor White
Write-Host "  Module: Mw05Recomp.exe" -ForegroundColor White
Write-Host "  Base address: 0x7ff620b70000 (varies per run)" -ForegroundColor White
Write-Host "  Crash address: base + 0x19DCA5" -ForegroundColor White
Write-Host ""

Write-Host "GUEST ADDRESS INFORMATION:" -ForegroundColor Yellow
Write-Host "  Guest base: 0x82000000" -ForegroundColor White
Write-Host "  Guest crash address: 0x8219DCA5 (approximately)" -ForegroundColor White
Write-Host ""

Write-Host "TO DEBUG WITH VISUAL STUDIO:" -ForegroundColor Yellow
Write-Host "  1. Open Mw05Recomp.sln in Visual Studio" -ForegroundColor White
Write-Host "  2. Set configuration to 'Debug'" -ForegroundColor White
Write-Host "  3. Set environment variables:" -ForegroundColor White
Write-Host "     MW05_FORCE_GFX_NOTIFY_CB=1" -ForegroundColor Gray
Write-Host "     MW05_FORCE_GFX_NOTIFY_CB_CTX=0x40007180" -ForegroundColor Gray
Write-Host "     MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS=450" -ForegroundColor Gray
Write-Host "     MW05_GFX_CALLBACK_FREQUENCY=10" -ForegroundColor Gray
Write-Host "     MW05_GFX_CALLBACK_MAX_INVOCATIONS=0" -ForegroundColor Gray
Write-Host "  4. Press F5 to start debugging" -ForegroundColor White
Write-Host "  5. When it crashes, examine:" -ForegroundColor White
Write-Host "     - Call stack" -ForegroundColor Gray
Write-Host "     - Registers (especially the one being accessed)" -ForegroundColor Gray
Write-Host "     - Memory at the faulting address" -ForegroundColor Gray
Write-Host "     - Disassembly around the crash" -ForegroundColor Gray
Write-Host ""

Write-Host "TO DEBUG WITH WINDBG:" -ForegroundColor Yellow
Write-Host "  1. Run: windbg -g Mw05Recomp.exe" -ForegroundColor White
Write-Host "  2. Set environment variables (same as above)" -ForegroundColor White
Write-Host "  3. When it crashes, run:" -ForegroundColor White
Write-Host "     !analyze -v" -ForegroundColor Gray
Write-Host "     r" -ForegroundColor Gray
Write-Host "     k" -ForegroundColor Gray
Write-Host "     u @rip" -ForegroundColor Gray
Write-Host ""

Write-Host "WHAT TO LOOK FOR:" -ForegroundColor Yellow
Write-Host "  1. Which register is being accessed when it crashes?" -ForegroundColor White
Write-Host "  2. What value is in that register?" -ForegroundColor White
Write-Host "  3. Is it NULL or an invalid address?" -ForegroundColor White
Write-Host "  4. Trace back: where was that register loaded from?" -ForegroundColor White
Write-Host "  5. Is it loading from a global variable?" -ForegroundColor White
Write-Host "  6. What is the guest address of that global?" -ForegroundColor White
Write-Host ""

Write-Host "EXPECTED FINDINGS:" -ForegroundColor Yellow
Write-Host "  - The crash is likely accessing a NULL pointer or uninitialized global" -ForegroundColor White
Write-Host "  - The global is probably in the range 0x82000000-0x83000000" -ForegroundColor White
Write-Host "  - We need to find what that global is and initialize it" -ForegroundColor White
Write-Host ""

Write-Host "Press Enter to run the game with delay=450 (will crash)..." -ForegroundColor Cyan
Read-Host

# Set environment variables
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "450"
$env:MW05_GFX_CALLBACK_FREQUENCY = "10"
$env:MW05_GFX_CALLBACK_MAX_INVOCATIONS = "0"

Write-Host "Running game..." -ForegroundColor Green
& ".\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"

Write-Host "`nExit code: $LASTEXITCODE" -ForegroundColor Yellow
Write-Host ""
Write-Host "If you have a crash dump, analyze it with:" -ForegroundColor Cyan
Write-Host "  windbg -z <dump_file>" -ForegroundColor White

