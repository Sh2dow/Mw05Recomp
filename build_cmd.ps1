# --- build_cmd.ps1: Staged helper for MW05 build ---

param(
    [ValidateSet('all', '0', 'configure', '1', 'codegen', '2', 'genlist', '3', 'lib', '4', 'app', '5', 'patch', '6')]
    [string]$Stage,
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel')]
    [string]$Config = 'Debug',
    [ValidateSet('x64-Clang-Debug', 'x64-Clang-Release', 'x64-Clang-RelWithDebInfo', 'x64-Clang-MinSizeRel')]
    [string]$Preset,
    [switch]$Clean,
    [switch]$DisableAppPch,
    [string]$ModuleName,
    [switch]$SharedRC
)

# --- 0) Paths & tools (unified + idempotent) ---
# Repo root (script lives in repo root)
$Repo = (Resolve-Path $PSScriptRoot).Path -replace '\\', '/'

$root = "C:\Program Files (x86)\Windows Kits\10"
$latestSdk = "10.0.26100.0"
$VS = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$MSVC = Join-Path $VS "VC\Tools\MSVC\14.44.35207"
$VCBIN = Join-Path $MSVC "bin\Hostx64\x64"
$VCLIB = Join-Path $MSVC "lib\x64"
$VSINC = Join-Path $MSVC "include"
$SDKINC = Join-Path $root "Include\$latestSdk"
$UCRTINC = Join-Path $SDKINC "ucrt"
$SHAREDINC = Join-Path $SDKINC "shared"
$UMINc = Join-Path $SDKINC "um"
$WINRTINC = Join-Path $SDKINC "winrt"
$CPPWINRTINC = Join-Path $SDKINC "cppwinrt"
$UCRTLIB = Join-Path $root "Lib\$latestSdk\ucrt\x64"
$UMLIB = Join-Path $root "Lib\$latestSdk\um\x64"

# Prefer standalone LLVM first
$LLVM_CANDIDATES = @(
    "$env:LLVM_HOME\bin",
    "C:\Program Files\LLVM\bin",
    (Join-Path $VS "VC\Tools\Llvm\x64\bin")
) | Where-Object { $_ -and (Test-Path $_) }
if ($LLVM_CANDIDATES.Count -gt 0)
{
    $LLVM = $LLVM_CANDIDATES[0]
}
else
{
    throw "No LLVM toolchain found."
}

# Normalize tool paths for CMake cache entries
$LLVM_CL = (Join-Path $LLVM "clang-cl.exe") -replace '\\', '/'
$LLVM_MT = (Join-Path $LLVM "llvm-mt.exe") -replace '\\', '/'
$LLVM_LINK = (Join-Path $LLVM "lld-link.exe") -replace '\\', '/'
$RC = (Join-Path $root "bin\$latestSdk\x64\rc.exe") -replace '\\', '/'
$MT = if (Test-Path $LLVM_MT)
{
    $LLVM_MT
}
else
{
    (Join-Path $LLVM "llvm-mt.exe") -replace '\\', '/'
}

# Idempotent env wiring ONCE per shell (sets INCLUDE/LIB/PATH in same block)
if (-not $env:MW05_ENV_INIT)
{
    # INCLUDE / LIB for MSVC + WinSDK headers/libs
    $env:INCLUDE = ($VSINC, $UCRTINC, $SHAREDINC, $UMINc, $WINRTINC, $CPPWINRTINC) -join ';'
    $env:LIB = "$VCLIB;$UCRTLIB;$UMLIB"

    # PATH (put MSVC, WinSDK bin, and chosen LLVM first)
    $env:PATH = "$LLVM;$VCBIN;$( Join-Path $root "bin\$latestSdk\x64" );$env:PATH"

    # CMake hints for Windows SDK
    $env:WindowsSdkDir = ($root -replace '\\', '/') + "/"
    $env:WindowsSDKVersion = "$latestSdk/"
    $env:CMAKE_SH = 'CMAKE_SH-NOTFOUND'

    $env:MW05_ENV_INIT = '1'
}
else
{
    Write-Host "[env] Using existing INCLUDE/LIB/PATH (MW05_ENV_INIT=1)" -ForegroundColor DarkGray
}

# vcpkg locations (robust, repo-relative)
$VCPKG = "$Repo/thirdparty/vcpkg"
$toolchain = (Resolve-Path "$VCPKG\scripts\buildsystems\vcpkg.cmake").Path

$D3D12 = (Join-Path $root "Lib\$latestSdk\um\x64\d3d12.lib") -replace '\\', '/'
# Derive preset/build dir from configuration or explicit preset
if ($PSBoundParameters.ContainsKey('Preset') -and $Preset)
{
    $preset = $Preset
    if ( $PSBoundParameters.ContainsKey('Config'))
    {
        if ($preset -match 'x64-Clang-(.+)$')
        {
            $presetConfig = $matches[1]
            if ($Config -ne $presetConfig)
            {
                Write-Host "[config] Requested Config '$Config' differs from Preset '$presetConfig'. Using preset." -ForegroundColor Yellow
                $Config = $presetConfig
            }
        }
    }
    else
    {
        if ($preset -match 'x64-Clang-(.+)$')
        {
            $Config = $matches[1]
        }
    }
}
else
{
    $preset = "x64-Clang-$Config"
}

$buildDir = "$Repo/out/build/$preset"
$exe = "$Repo/out/build/$preset/tools/XenonRecomp/XenonRecomp/XenonRecomp.exe"
# clean outputs so Ninja MUST run the rule
$ppc = "$Repo/Mw05RecompLib/ppc"               # keep folder name as in repo
$patched = "$Repo/Mw05RecompLib/private/default_patched.xex"
$VCPKG_INST = "$buildDir/vcpkg_installed/x64-windows-static" -replace '\\', '/'
$FT_DIR = "$VCPKG_INST/share/freetype"
$FT_LIB = "$VCPKG_INST/lib/freetype.lib"
$FT_INC = "$VCPKG_INST/include"

if (-not (Test-Path $ppc))
{
    New-Item -ItemType Directory $ppc | Out-Null
}

# --- Safe removal of generated paths inside the *build* tree only ---
function SafeRemove-GeneratedPath
{
    param(
        [Parameter(Mandatory = $true)][string]$TargetPath, # e.g. "$buildDir/tools/XenosRecomp/thirdparty/zstd"
        [Parameter(Mandatory = $true)][string]$BuildRoot, # e.g. $buildDir
        [switch]$VerboseLog
    )

    try
    {
        if (-not (Test-Path -LiteralPath $TargetPath))
        {
            if ($VerboseLog)
            {
                Write-Host "[clean] skip (not found): $TargetPath" -ForegroundColor DarkGray
            }
            return
        }

        # Normalize & resolve to absolute, forward slashes for reliable prefix check
        $resolvedTarget = (Resolve-Path -LiteralPath $TargetPath).Path -replace '\\', '/'
        $resolvedBuild = (Resolve-Path -LiteralPath $BuildRoot).Path -replace '\\', '/'

        # 1) Must be inside the build root
        if (-not $resolvedTarget.StartsWith($resolvedBuild, [System.StringComparison]::OrdinalIgnoreCase))
        {
            Write-Warning "[clean] Refusing to delete outside of build dir: $resolvedTarget (build root: $resolvedBuild)"
            return
        }

        # 2) Must NOT be a git repo (no .git dir anywhere beneath)
        $hasGit = Test-Path -LiteralPath (Join-Path $TargetPath '.git') -PathType Container
        if (-not $hasGit)
        {
            # Check nested .git too (hidden)
            $gitNodes = Get-ChildItem -LiteralPath $TargetPath -Force -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer -and $_.Name -eq '.git' } | Select-Object -First 1
            $hasGit = [bool]$gitNodes
        }
        if ($hasGit)
        {
            Write-Warning "[clean] Refusing to delete VCS content (.git found): $resolvedTarget"
            return
        }

        # 3) Should look like a CMake/Ninja generated subtree
        $looksGenerated =    `
         (Test-Path -LiteralPath (Join-Path $TargetPath 'CMakeFiles')) -or    `
         (Test-Path -LiteralPath (Join-Path $TargetPath 'build.ninja')) -or    `
         (Test-Path -LiteralPath (Join-Path $TargetPath 'CMakeCache.txt')) -or    `
         (Test-Path -LiteralPath (Join-Path $TargetPath 'cmake_install.cmake'))

        if (-not $looksGenerated)
        {
            Write-Warning "[clean] Refusing to delete (doesn't look generated): $resolvedTarget"
            return
        }

        # 4) All checks passed — delete
        if ($VerboseLog)
        {
            Write-Host "[clean] Removing: $resolvedTarget" -ForegroundColor Yellow
        }
        Remove-Item -LiteralPath $TargetPath -Recurse -Force -ErrorAction Stop
    }
    catch
    {
        Write-Warning ("[clean] Failed to remove '{0}': {1}" -f $TargetPath, $_.Exception.Message)
    }
}

function Reset-BuildDirWithKeep
{
    param(
        [Parameter(Mandatory = $true)][string]$BuildRoot,
        [string[]]$KeepRel = @(),
        [switch]$VerboseLog
    )

    # Temp staging area
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("mw05_keep_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null

    $kept = @()
    foreach ($rel in $KeepRel)
    {
        $src = Join-Path $BuildRoot $rel
        if (Test-Path -LiteralPath $src)
        {
            $dst = Join-Path $temp $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            if ($VerboseLog)
            {
                Write-Host "[Clean] Preserving $rel" -ForegroundColor DarkYellow
            }
            Move-Item -LiteralPath $src -Destination $dst -Force
            $kept += ,@($rel, $dst)
        }
        elseif ($VerboseLog)
        {
            Write-Host "[Clean] Not found (skip preserve): $rel" -ForegroundColor DarkGray
        }
    }

    # Wipe build root
    if (Test-Path -LiteralPath $BuildRoot)
    {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null

    # Restore preserved subtrees
    foreach ($pair in $kept)
    {
        $rel = $pair[0]; $dst = $pair[1]
        $restoreTarget = Join-Path $BuildRoot $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $restoreTarget) | Out-Null
        Move-Item -LiteralPath $dst -Destination $restoreTarget -Force
        if ($VerboseLog)
        {
            Write-Host "[Clean] Restored $rel" -ForegroundColor DarkYellow
        }
    }

    # Cleanup temp
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($Clean)
{
    # Normal clean: remove generated sources and app PCH
    Write-Host "[Clean] Performing safe cleanup..." -ForegroundColor Yellow

    # Remove only generated sources; keep .gitignore and any manual files
    Get-ChildItem -Path $ppc -Force -File -Filter 'ppc_recomp.*.cpp' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    if (Test-Path $patched)
    {
        Remove-Item -Force $patched
    }
    # Also clear app PCH so it rebuilds under current toolset
    $appPchDir = "$Repo/out/build/$preset/Mw05Recomp/CMakeFiles/Mw05Recomp.dir"
    Get-ChildItem -Path $appPchDir -Force -ErrorAction SilentlyContinue -Filter 'cmake_pch*' | Remove-Item -Force -ErrorAction SilentlyContinue

    # Clear Zstd build dir only if it's stale (points into /build/cmake) or user explicitly cleaned
    $zstdCmakeDir = Join-Path $Repo "tools/XenosRecomp/thirdparty/zstd/build/cmake"
    if (-not (Test-Path $zstdCmakeDir))
    {
        Write-Host "[Clean] Zstd build dir is stale; removing thirdparty/zstd/build" -ForegroundColor DarkYellow
        Remove-Item -Recurse -Force "$Repo/tools/XenosRecomp/thirdparty/zstd/build" -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Host "[Clean] Zstd build dir looks valid; leaving intact" -ForegroundColor DarkGray
    }
}

# Interactive stage selection if not provided
if (-not $PSBoundParameters.ContainsKey('Stage'))
{
    Write-Host "Select build stage:" -ForegroundColor Cyan
    Write-Host "  [a] All (configure → codegen → genlist → lib → app)"
    Write-Host "  [0] Configure"
    Write-Host "  [1] Codegen"
    Write-Host "  [2] Generate file list + reconfigure"
    Write-Host "  [3] Build library"
    Write-Host "  [4] Build app"
    Write-Host "  [6] Patch XEX only (run XenonRecomp)"
    $sel = Read-Host "Enter choice (a/0/1/2/3/4) [default: a]"
    if ( [string]::IsNullOrWhiteSpace($sel))
    {
        $Stage = 'all'
    }
    else
    {
        switch ($sel)
        {
            'a' {
                $Stage = 'all'
            }
            '0' {
                $Stage = 'configure'
            }
            '1' {
                $Stage = 'codegen'
            }
            '2' {
                $Stage = 'genlist'
            }
            '3' {
                $Stage = 'lib'
            }
            '4' {
                $Stage = 'app'
            }
            '6' {
                $Stage = 'patch'
            }
            default {
                $Stage = 'all'
            }
        }
    }
}

function Invoke-Configure
{
    Write-Host "[Stage] Configure (fresh=$Clean)"
    $freshArgs = @()
    if ($Clean)
    {
        $freshArgs += '--fresh'
    }

    $pchArg = @()
    if ($DisableAppPch)
    {
        $pchArg += '-D'; $pchArg += 'MW05_SKIP_APP_PCH=ON'
    }

    $modArg = @()
    if ($PSBoundParameters.ContainsKey('ModuleName') -and $ModuleName)
    {
        $modArg += '-D'; $modArg += "MW05_MODULE_NAME=$ModuleName"
    }

    # Normalized repo path (once, near top of script is fine too)
    if (-not $script:Repo)
    {
        $script:Repo = (Resolve-Path $PSScriptRoot).Path -replace '\\', '/'
    }
    $ZstdLib = (Resolve-Path "$Repo/tools/XenosRecomp/thirdparty/zstd/lib").Path -replace '\\', '/'

    # If you toggle mode or use -Clean, clear zstd's cached build
    if ($Clean)
    {
        SafeRemove-GeneratedPath -TargetPath "$buildDir/tools/XenosRecomp/thirdparty/zstd" -BuildRoot "$buildDir" -VerboseLog

        # Preinstall the manifest into the SAME build tree CMake will use
        $env:VCPKG_ROOT = $Vcpkg
        & "$Vcpkg/bootstrap-vcpkg.bat"

        # Clean previous build so paths are fresh, but keep Mw05Recomp\game and \update
        Reset-BuildDirWithKeep -BuildRoot $buildDir `
            -KeepRel @("Mw05Recomp\game", "Mw05Recomp\update") `
            -VerboseLog

        # Install the manifest (NO package names) into the build’s vcpkg_installed/
        & "$Vcpkg/vcpkg.exe" install --triplet x64-windows-static --host-triplet x64-windows-static `
        --x-install-root="$buildDir/vcpkg_installed"
    }

    # zstd args: default = static only; with -SharedRC = shared+static and RC include fix
    $zstdArgs = @()
    if ($SharedRC)
    {
        $zstdArgs += @(
            '-D', 'ZSTD_BUILD_SHARED=ON',
            '-D', 'ZSTD_BUILD_STATIC=ON',
            '-D', 'ZSTD_BUILD_PROGRAMS=OFF',
            '-D', 'ZSTD_BUILD_TESTS=OFF',
            # Properly quoted include for RC (handles spaces)
            '-D', ("CMAKE_RC_FLAGS=/I `"$ZstdLib`"")
        )
    }
    else
    {
        $zstdArgs += @(
            '-D', 'ZSTD_BUILD_SHARED=OFF',
            '-D', 'ZSTD_BUILD_STATIC=ON',
            '-D', 'ZSTD_BUILD_PROGRAMS=OFF',
            '-D', 'ZSTD_BUILD_TESTS=OFF'
        )
    }

    cmake --preset $preset @freshArgs `
    -D CMAKE_C_COMPILER:FILEPATH="$LLVM_CL" `
    -D CMAKE_CXX_COMPILER:FILEPATH="$LLVM_CL" `
    -D CMAKE_LINKER:FILEPATH="$LLVM_LINK" `
    -D CMAKE_RC_COMPILER:FILEPATH="$RC" `
    -D CMAKE_MT:FILEPATH="$LLVM_MT" `
    -D CMAKE_TOOLCHAIN_FILE="$toolchain" `
    -D VCPKG_TARGET_TRIPLET="x64-windows-static" `
    -D VCPKG_HOST_TRIPLET="x64-windows-static" `
    -D CMAKE_FIND_PACKAGE_PREFER_CONFIG=ON `
    -D CMAKE_PREFIX_PATH="$VCPKG_INST;$VCPKG_INST/share;$VCPKG_INST/lib/cmake" `
    -D Freetype_DIR="$FT_DIR" `
    -D FREETYPE_LIBRARY="$FT_LIB" `
    -D FREETYPE_INCLUDE_DIRS="$FT_INC" `
    -D CMAKE_BUILD_TYPE=$Config `
    -D CMAKE_SYSTEM_VERSION="$latestSdk" `
    -D CMAKE_SH=CMAKE_SH-NOTFOUND `
    `
    @zstdArgs `
    -D MW05_RECOMP_SKIP_CODEGEN=OFF `
    -D CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF `
    -D MW05_GEN_INDIRECT_REDIRECTS=ON `
    @pchArg `
    @modArg

}


# Helper tasks
function Ensure-Configured
{
    $ninja = Join-Path $buildDir 'build.ninja'
    if (-not (Test-Path $ninja))
    {
        Write-Host "[Stage] Configure (auto, missing build.ninja)" -ForegroundColor Yellow
        Invoke-Configure
    }
}

function Invoke-Codegen
{
    Write-Host "[Stage] Codegen (PPC)" -ForegroundColor Cyan
    Ensure-Configured
    $xex = "$Repo/Mw05RecompLib/private/default.xex"
    if (-not (Test-Path $xex))
    {
        Write-Host "Missing XEX: $xex" -ForegroundColor Red
        Write-Host "Place the game XEX there or pass -Stage configure to set paths." -ForegroundColor Yellow
        exit 1
    }
    $size = (Get-Item $xex).Length
    if ($size -lt 65536)
    {
        Write-Host "Suspicious XEX size ($size bytes): $xex" -ForegroundColor Yellow
    }
    Write-Host "Using XEX: $xex" -ForegroundColor Gray
    Write-Host "Using TOML: $Repo/Mw05RecompLib/config/MW05.toml" -ForegroundColor Gray
    cmake --build "$buildDir" --target PPCCodegen -j1 -v
}
function Invoke-Patch
{
    Write-Host "[Stage] Patch XEX (run XenonRecomp)" -ForegroundColor Cyan
    $xex = "$Repo/Mw05RecompLib/private/default.xex"
    $out = "$Repo/Mw05RecompLib/private/default_patched.xex"
    if (-not (Test-Path $xex))
    {
        Write-Host "Missing XEX: $xex" -ForegroundColor Red
        exit 1
    }
    # Ensure XenonRecomp is built
    cmake --build "$buildDir" --target XenonRecomp -j1 -v
    if (-not (Test-Path $exe))
    {
        Write-Host "XenonRecomp not found at $exe" -ForegroundColor Red
        exit 1
    }
    Write-Host "Running: $exe" -ForegroundColor Gray
    & $exe
    $ec = $LASTEXITCODE
    if ($ec -ne 0)
    {
        Write-Host ("XenonRecomp exited with code {0}" -f $ec) -ForegroundColor Yellow
    }
    if (Test-Path $out)
    {
        $sz = (Get-Item $out).Length
        Write-Host ("Patched XEX produced: {0} bytes" -f $sz) -ForegroundColor Green
    }
    else
    {
        Write-Host "Patched XEX was not produced. Check XenonRecomp output above." -ForegroundColor Red
    }
}
function Invoke-GenList
{
    Write-Host "[Stage] Generate PPC file list" -ForegroundColor Cyan
    $ppcDir = "$Repo/Mw05RecompLib/ppc"
    # Produce generated_sources.cmake only if PPC files exist
    cmake -P "$Repo/Mw05RecompLib/cmake/gen_ppc_list.cmake" | Out-Host
    $havePpc = @(Get-ChildItem $ppcDir -ErrorAction SilentlyContinue -Filter 'ppc_recomp.*.cpp').Count -gt 0
    if ($havePpc)
    {
        # Re-run configure with full toolchain args to pick up the new file list
        Invoke-Configure
    }
    else
    {
        Write-Host "No generated PPC sources yet; using fallback list. Skipping reconfigure." -ForegroundColor Yellow
    }
}
function Build-Lib
{
    Ensure-Configured; cmake --build "$buildDir" --target Mw05RecompLib -j1 -v
}
function Build-App
{
    Ensure-Configured
    # Ensure app PCH is rebuilt with the current toolset
    $appPchDir = "$Repo/out/build/$preset/Mw05Recomp/CMakeFiles/Mw05Recomp.dir"
    $removedPch = $false
    $toRemove = Get-ChildItem -Path $appPchDir -Force -ErrorAction SilentlyContinue -Filter 'cmake_pch*'
    if ($toRemove)
    {
        $toRemove | Remove-Item -Force -ErrorAction SilentlyContinue
        $removedPch = $true
    }
    # If we removed or if cmake_pch.cxx is missing, re-run configure to regenerate it
    $pchSource = Join-Path $appPchDir 'cmake_pch.cxx'
    if ($removedPch -or -not (Test-Path $pchSource))
    {
        # ✅ keep cache & compilers intact
        cmake -S "$Repo" -B "$buildDir" | Out-Host
    }

    cmake --build "$buildDir" --target Mw05Recomp -j1 -v
    $app = "$Repo/out/build/$preset/Mw05Recomp/Mw05Recomp.exe"
    if (Test-Path $app)
    {
        Write-Host ("App built: {0}" -f $app) -ForegroundColor Green
        Write-Host ("Run: `"{0}`"" -f $app)
        # Copy patched module next to the app for runtime loading
        $dstDir = Split-Path -Parent $app
        $dstXex = Join-Path $dstDir 'default_patched.xex'
        if (Test-Path $patched)
        {
            Copy-Item -Force $patched $dstXex
            Write-Host ("Synced patched module to: {0}" -f $dstXex) -ForegroundColor DarkGray
            # If a custom ModuleName is provided, sync under that name too
            if ($PSBoundParameters.ContainsKey('ModuleName') -and $ModuleName)
            {
                $dstCustom = Join-Path $dstDir $ModuleName
                if (!(Test-Path $dstCustom) -or ((Get-Item $dstCustom).FullName -ne (Get-Item $dstXex).FullName))
                {
                    Copy-Item -Force $patched $dstCustom
                    Write-Host ("Synced patched module to: {0}" -f $dstCustom) -ForegroundColor DarkGray
                }
            }
        }
        else
        {
            Write-Host ("Patched XEX not found: {0}. Build codegen first (Stage codegen/genlist)." -f $patched) -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host "App executable not found yet (build may have failed)." -ForegroundColor Yellow
    }
}

# Stage selection
switch ($Stage)
{
    'configure' {
        Invoke-Configure; break
    }
    '1'         {
        Invoke-Configure; break
    }
    'codegen'   {
        Invoke-Codegen; break
    }
    '2'         {
        Invoke-Codegen; break
    }
    'genlist'   {
        Invoke-GenList; break
    }
    '3'         {
        Invoke-GenList; break
    }
    'patch'     {
        Invoke-Patch; break
    }
    '6'         {
        Invoke-Patch; break
    }
    'lib'       {
        Build-Lib; break
    }
    '4'         {
        Build-Lib; break
    }
    'app'       {
        Build-App; break
    }
    '5'         {
        Build-App; break
    }
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
function Summarize-PPC
{
    param([string]$Dir = "$Repo/Mw05RecompLib/ppc")
    $files = Get-ChildItem $Dir -Filter 'ppc_recomp.*.cpp' -ErrorAction SilentlyContinue
    $count = $files.Count
    Write-Host ("Generated PPC sources: {0}" -f $count)
    if ($count -eq 0)
    {
        return
    }
    $indices = @()
    foreach ($f in $files)
    {
        if ($f.BaseName -match 'ppc_recomp\.(\d+)$')
        {
            $indices += [int]$matches[1]
        }
    }
    if ($indices.Count -gt 0)
    {
        $min = ($indices | Measure-Object -Minimum).Minimum
        $max = ($indices | Measure-Object -Maximum).Maximum
        $span = $max - $min + 1
        $set = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($i in $indices)
        {
            [void]$set.Add($i)
        }
        $missing = @()
        for ($i = $min; $i -le $max; $i++) {
            if (-not $set.Contains($i))
            {
                $missing += $i
            }
        }
        Write-Host ("Index range: {0}..{1} (span {2}), missing: {3}" -f $min, $max, $span, $missing.Count)
        if ($missing.Count -gt 0 -and $missing.Count -le 20)
        {
            Write-Host ("Missing indices: {0}" -f ($missing -join ', '))
        }
    }
    $oldest = $files | Sort-Object LastWriteTime | Select-Object -First 1
    $newest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($oldest)
    {
        Write-Host ("Oldest: {0}  {1}" -f $oldest.Name, $oldest.LastWriteTime)
    }
    if ($newest)
    {
        Write-Host ("Newest: {0}  {1}" -f $newest.Name, $newest.LastWriteTime)
    }
    $genList = "$Repo/Mw05RecompLib/ppc/generated_sources.cmake"
    if (Test-Path $genList)
    {
        $lines = (Get-Content $genList -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
        Write-Host ("generated_sources.cmake lines: {0}" -f $lines)
    }
}

# If we just ran genlist, summarize immediately for convenience
if ($Stage -eq 'genlist' -or $Stage -eq '3' -or $Stage -eq 'all')
{
    Summarize-PPC
}

# Always print a brief summary at the end
Summarize-PPC
