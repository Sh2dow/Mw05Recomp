@echo off
cd out\build\x64-Clang-Debug\Mw05Recomp
taskkill /F /IM Mw05Recomp.exe 2>nul
del stderr_fresh.txt 2>nul
start /B Mw05Recomp.exe 2>stderr_fresh.txt
timeout /T 15 /NOBREAK >nul
taskkill /F /IM Mw05Recomp.exe 2>nul
timeout /T 2 /NOBREAK >nul
findstr /C:"MW05_FIX" /C:"ExCreateThread" /C:"THREAD_828508A8" /C:"WRAPPER_82812ED0" stderr_fresh.txt

