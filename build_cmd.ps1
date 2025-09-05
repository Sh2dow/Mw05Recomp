# --- build_cmd.ps1: Staged helper for MW05 build ---

param(
  [ValidateSet('all','0','configure','1','codegen','2','genlist','3','lib','4','app','5','patch','6')]
  [string]$Stage,
  [ValidateSet('Debug','Release','RelWithDebInfo','MinSizeRel')]
  [string]$Config = 'Release',
  [switch]$Clean,
  [switch]$DisableAppPch,
  [string]$ModuleName
)

# --- 0) Paths & tools (keep as-is) ---
$root     = "C:\Program Files (x86)\Windows Kits\10"
$latestSdk= "10.0.26100.0"
$VS = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$MSVC = Join-Path $VS "VC\Tools\MSVC\14.44.35207"
$LLVM = Join-Path $VS "VC\Tools\Llvm\x64\bin"
$VSINC = Join-Path $MSVC "include"
$SDKINC= Join-Path $root "Include\$latestSdk"
$VCBIN = Join-Path $MSVC "bin\Hostx64\x64"
$VCLIB = Join-Path $MSVC "lib\x64"
$UCRTINC = Join-Path $SDKINC "ucrt"
$SHAREDINC = Join-Path $SDKINC "shared"
$UMINc = Join-Path $SDKINC "um"
$WINRTINC = Join-Path $SDKINC "winrt"
$CPPWINRTINC = Join-Path $SDKINC "cppwinrt"
$UCRTLIB = Join-Path $root "Lib\$latestSdk\ucrt\x64"
$UMLIB = Join-Path $root "Lib\$latestSdk\um\x64"

# INCLUDE
$includeParts = @($VSINC,$UCRTINC,$SHAREDINC,$UMINc,$WINRTINC,$CPPWINRTINC)
if ($env:INCLUDE) {
  $env:INCLUDE = ($includeParts -join ';') + ';' + $env:INCLUDE
} else {
  $env:INCLUDE = ($includeParts -join ';')
}

# LIB
if ($env:LIB) {
  $env:LIB = "$VCLIB;$UCRTLIB;$UMLIB;" + $env:LIB
} else {
  $env:LIB = "$VCLIB;$UCRTLIB;$UMLIB"
}

# PATH
$env:PATH = "$VCBIN;" + (Join-Path $root "bin\$latestSdk\x64") + ';' + $LLVM + ';' + $env:PATH
$env:WindowsSdkDir     = ($root -replace '\\','/') + "/"
$env:WindowsSDKVersion = "$latestSdk/"
$env:CMAKE_SH = 'CMAKE_SH-NOTFOUND'
$RC    = (Join-Path $root "bin\$latestSdk\x64\rc.exe") -replace '\\','/'
$MT    = (Join-Path $LLVM "llvm-mt.exe")               -replace '\\','/'
$D3D12 = (Join-Path $root "Lib\$latestSdk\um\x64\d3d12.lib") -replace '\\','/'
$toolchain = "D:/Repos/Games/MW05Recomp/thirdparty/vcpkg/scripts/buildsystems/vcpkg.cmake"
# Derive preset/build dir from configuration
$preset = "x64-Clang-$Config"
$buildDir = "D:/Repos/Games/MW05Recomp/out/build/$preset"
$exe = "D:/Repos/Games/MW05Recomp/out/build/$preset/tools/XenonRecomp/XenonRecomp/XenonRecomp.exe"
# clean outputs so Ninja MUST run the rule
$ppc = 'D:/Repos/Games/MW05Recomp/Mw05RecompLib/ppc'
$patched = 'D:/Repos/Games/MW05Recomp/Mw05RecompLib/private/default_patched.xex'
if (-not (Test-Path $ppc)) { New-Item -ItemType Directory $ppc | Out-Null }
if ($Clean) {
  # Remove only generated sources; keep .gitignore and any manual files
  Get-ChildItem -Path $ppc -Force -File -Filter 'ppc_recomp.*.cpp' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
  if (Test-Path $patched) { Remove-Item -Force $patched }
  # Also clear app PCH so it rebuilds under current toolset
  $appPchDir = "D:/Repos/Games/MW05Recomp/out/build/$preset/Mw05Recomp/CMakeFiles/Mw05Recomp.dir"
  Get-ChildItem -Path $appPchDir -Force -ErrorAction SilentlyContinue -Filter 'cmake_pch*' | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Interactive stage selection if not provided
if (-not $PSBoundParameters.ContainsKey('Stage')) {
  Write-Host "Select build stage:" -ForegroundColor Cyan
  Write-Host "  [a] All (configure → codegen → genlist → lib → app)"
  Write-Host "  [0] Configure"
  Write-Host "  [1] Codegen"
  Write-Host "  [2] Generate file list + reconfigure"
  Write-Host "  [3] Build library"
  Write-Host "  [4] Build app"
  Write-Host "  [6] Patch XEX only (run XenonRecomp)"
  $sel = Read-Host "Enter choice (a/0/1/2/3/4) [default: a]"
  if ([string]::IsNullOrWhiteSpace($sel)) { $Stage = 'all' }
  else {
    switch ($sel) {
      'a' { $Stage = 'all' }
      '0' { $Stage = 'configure' }
      '1' { $Stage = 'codegen' }
      '2' { $Stage = 'genlist' }
      '3' { $Stage = 'lib' }
      '4' { $Stage = 'app' }
      '6' { $Stage = 'patch' }
      default { $Stage = 'all' }
    }
  }
}

function Invoke-Configure {
  Write-Host "[Stage] Configure (fresh=$Clean)"
  $freshArgs = @()
  if ($Clean) { $freshArgs += '--fresh' }
  $pchArg = @()
  if ($DisableAppPch) { 
    $pchArg += '-D'; $pchArg += 'MW05_SKIP_APP_PCH=ON'
  }
  $modArg = @()
  if ($PSBoundParameters.ContainsKey('ModuleName') -and $ModuleName) {
    $modArg += '-D'; $modArg += "MW05_MODULE_NAME=$ModuleName"
  }
  cmake --preset $preset @freshArgs `
    -D CMAKE_C_COMPILER="$LLVM/clang-cl.exe" `
    -D CMAKE_CXX_COMPILER="$LLVM/clang-cl.exe" `
    -D CMAKE_TOOLCHAIN_FILE="$toolchain" `
    -D VCPKG_TARGET_TRIPLET="x64-windows-static" `
    -D CMAKE_BUILD_TYPE=$Config `
    -D CMAKE_SYSTEM_VERSION="$latestSdk" `
    -D CMAKE_RC_COMPILER="$RC" `
    -D CMAKE_MT="$MT" `
    -D CMAKE_SH=CMAKE_SH-NOTFOUND `
    `
    -D MW05_RECOMP_SKIP_CODEGEN=OFF `
    -D CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF `
    @pchArg `
    @modArg
}

# Helper tasks
function Invoke-Codegen {
  Write-Host "[Stage] Codegen (PPC)" -ForegroundColor Cyan
  $xex = "D:/Repos/Games/MW05Recomp/Mw05RecompLib/private/default.xex"
  if (-not (Test-Path $xex)) {
    Write-Host "Missing XEX: $xex" -ForegroundColor Red
    Write-Host "Place the game XEX there or pass -Stage configure to set paths." -ForegroundColor Yellow
    exit 1
  }
  $size = (Get-Item $xex).Length
  if ($size -lt 65536) {
    Write-Host "Suspicious XEX size ($size bytes): $xex" -ForegroundColor Yellow
  }
  Write-Host "Using XEX: $xex" -ForegroundColor Gray
  Write-Host "Using TOML: D:/Repos/Games/MW05Recomp/Mw05RecompLib/config/MW05.toml" -ForegroundColor Gray
  cmake --build "$buildDir" --target PPCCodegen -j1 -v
}
function Invoke-Patch {
  Write-Host "[Stage] Patch XEX (run XenonRecomp)" -ForegroundColor Cyan
  $xex = "D:/Repos/Games/MW05Recomp/Mw05RecompLib/private/default.xex"
  $out = "D:/Repos/Games/MW05Recomp/Mw05RecompLib/private/default_patched.xex"
  if (-not (Test-Path $xex)) {
    Write-Host "Missing XEX: $xex" -ForegroundColor Red
    exit 1
  }
  # Ensure XenonRecomp is built
  cmake --build "$buildDir" --target XenonRecomp -j1 -v
  if (-not (Test-Path $exe)) {
    Write-Host "XenonRecomp not found at $exe" -ForegroundColor Red
    exit 1
  }
  Write-Host "Running: $exe" -ForegroundColor Gray
  & $exe
  $ec = $LASTEXITCODE
  if ($ec -ne 0) {
    Write-Host ("XenonRecomp exited with code {0}" -f $ec) -ForegroundColor Yellow
  }
  if (Test-Path $out) {
    $sz = (Get-Item $out).Length
    Write-Host ("Patched XEX produced: {0} bytes" -f $sz) -ForegroundColor Green
  } else {
    Write-Host "Patched XEX was not produced. Check XenonRecomp output above." -ForegroundColor Red
  }
}
function Invoke-GenList {
  Write-Host "[Stage] Generate PPC file list" -ForegroundColor Cyan
  $ppcDir = "D:/Repos/Games/MW05Recomp/Mw05RecompLib/ppc"
  # Produce generated_sources.cmake only if PPC files exist
  cmake -P "D:/Repos/Games/MW05Recomp/Mw05RecompLib/cmake/gen_ppc_list.cmake" | Out-Host
  $havePpc = @(Get-ChildItem $ppcDir -ErrorAction SilentlyContinue -Filter 'ppc_recomp.*.cpp').Count -gt 0
  if ($havePpc) {
    # Re-run configure with full toolchain args to pick up the new file list
    Invoke-Configure
  } else {
    Write-Host "No generated PPC sources yet; using fallback list. Skipping reconfigure." -ForegroundColor Yellow
  }
}
function Build-Lib    { cmake --build "$buildDir" --target Mw05RecompLib -j1 -v }
function Build-App    {
  # Ensure app PCH is rebuilt with the current toolset
  $appPchDir = "D:/Repos/Games/MW05Recomp/out/build/$preset/Mw05Recomp/CMakeFiles/Mw05Recomp.dir"
  $removedPch = $false
  $toRemove = Get-ChildItem -Path $appPchDir -Force -ErrorAction SilentlyContinue -Filter 'cmake_pch*'
  if ($toRemove) {
    $toRemove | Remove-Item -Force -ErrorAction SilentlyContinue
    $removedPch = $true
  }
  # If we removed or if cmake_pch.cxx is missing, re-run configure to regenerate it
  $pchSource = Join-Path $appPchDir 'cmake_pch.cxx'
  if ($removedPch -or -not (Test-Path $pchSource)) {
    cmake --preset $preset | Out-Host
  }

  cmake --build "$buildDir" --target Mw05Recomp -j1 -v
  $app = "D:/Repos/Games/MW05Recomp/out/build/$preset/Mw05Recomp/Mw05Recomp.exe"
  if (Test-Path $app) {
    Write-Host ("App built: {0}" -f $app) -ForegroundColor Green
    Write-Host ("Run: `"{0}`"" -f $app)
    # Copy patched module next to the app for runtime loading
    $dstDir = Split-Path -Parent $app
    $dstXex = Join-Path $dstDir 'default_patched.xex'
    if (Test-Path $patched) {
      Copy-Item -Force $patched $dstXex
      Write-Host ("Synced patched module to: {0}" -f $dstXex) -ForegroundColor DarkGray
      # If a custom ModuleName is provided, sync under that name too
      if ($PSBoundParameters.ContainsKey('ModuleName') -and $ModuleName) {
        $dstCustom = Join-Path $dstDir $ModuleName
        if (!(Test-Path $dstCustom) -or ((Get-Item $dstCustom).FullName -ne (Get-Item $dstXex).FullName)) {
          Copy-Item -Force $patched $dstCustom
          Write-Host ("Synced patched module to: {0}" -f $dstCustom) -ForegroundColor DarkGray
        }
      }
    } else {
      Write-Host ("Patched XEX not found: {0}. Build codegen first (Stage codegen/genlist)." -f $patched) -ForegroundColor Yellow
    }
  } else {
    Write-Host "App executable not found yet (build may have failed)." -ForegroundColor Yellow
  }
}

# Stage selection
switch ($Stage) {
  'configure' { Invoke-Configure; break }
  '1'         { Invoke-Configure; break }
  'codegen'   { Invoke-Codegen; break }
  '2'         { Invoke-Codegen; break }
  'genlist'   { Invoke-GenList; break }
  '3'         { Invoke-GenList; break }
  'patch'     { Invoke-Patch; break }
  '6'         { Invoke-Patch; break }
  'lib'       { Build-Lib; break }
  '4'         { Build-Lib; break }
  'app'       { Build-App; break }
  '5'         { Build-App; break }
  default {
    # all
    Invoke-Configure
    Invoke-Codegen
    Invoke-GenList
    Build-Lib
    Build-App
  }
}

# Summary / verification
function Summarize-PPC {
  param([string]$Dir = 'D:/Repos/Games/MW05Recomp/Mw05RecompLib/ppc')
  $files = Get-ChildItem $Dir -Filter 'ppc_recomp.*.cpp' -ErrorAction SilentlyContinue
  $count = $files.Count
  Write-Host ("Generated PPC sources: {0}" -f $count)
  if ($count -eq 0) { return }
  $indices = @()
  foreach ($f in $files) {
    if ($f.BaseName -match 'ppc_recomp\.(\d+)$') { $indices += [int]$matches[1] }
  }
  if ($indices.Count -gt 0) {
    $min = ($indices | Measure-Object -Minimum).Minimum
    $max = ($indices | Measure-Object -Maximum).Maximum
    $span = $max - $min + 1
    $set = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($i in $indices) { [void]$set.Add($i) }
    $missing = @()
    for ($i = $min; $i -le $max; $i++) { if (-not $set.Contains($i)) { $missing += $i } }
    Write-Host ("Index range: {0}..{1} (span {2}), missing: {3}" -f $min,$max,$span,$missing.Count)
    if ($missing.Count -gt 0 -and $missing.Count -le 20) {
      Write-Host ("Missing indices: {0}" -f ($missing -join ', '))
    }
  }
  $oldest = $files | Sort-Object LastWriteTime | Select-Object -First 1
  $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($oldest) { Write-Host ("Oldest: {0}  {1}" -f $oldest.Name, $oldest.LastWriteTime) }
  if ($newest) { Write-Host ("Newest: {0}  {1}" -f $newest.Name, $newest.LastWriteTime) }
  $genList = 'D:/Repos/Games/MW05Recomp/Mw05RecompLib/ppc/generated_sources.cmake'
  if (Test-Path $genList) {
    $lines = (Get-Content $genList -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    Write-Host ("generated_sources.cmake lines: {0}" -f $lines)
  }
}

# If we just ran genlist, summarize immediately for convenience
if ($Stage -eq 'genlist' -or $Stage -eq '3' -or $Stage -eq 'all') {
  Summarize-PPC
}

# Always print a brief summary at the end
Summarize-PPC
