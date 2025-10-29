# Simple build script that sets up environment and builds
# Usage: .\build_simple.ps1 [configure|build|all] [-Config Debug|Release|RelWithDebInfo|MinSizeRel] [-Preset x64-Clang-Debug|...] [-Clean]
#
# NOTE: This script is a simplified version that does NOT handle PPC codegen stages.
# For full builds with PPC code generation, use build_cmd.ps1 instead:
#   .\build_cmd.ps1 -Stage app -Config Debug
#
# This script is useful for:
# - Quick CMake configuration testing
# - Building after PPC sources have already been generated
# - Understanding the CMake setup without the complexity of staged builds

param(
    [ValidateSet('configure', 'build', 'all')]
    [string]$Action = 'all',

    [ValidateSet('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel')]
    [string]$Config = 'Debug',

    [ValidateSet('x64-Clang-Debug', 'x64-Clang-Release', 'x64-Clang-RelWithDebInfo', 'x64-Clang-MinSizeRel')]
    [string]$Preset,

    [switch]$Clean,

    [string[]]$KeepRel = @("Mw05Recomp\game", "Mw05Recomp\update")
)

# Repo root
$Repo = (Resolve-Path $PSScriptRoot).Path -replace '\\', '/'

# Derive preset from Config if not explicitly provided
if ($PSBoundParameters.ContainsKey('Preset') -and $Preset) {
    # Extract config from preset if provided
    if ($Preset -match 'x64-Clang-(.+)$') {
        $presetConfig = $matches[1]
        if ($PSBoundParameters.ContainsKey('Config') -and $Config -ne $presetConfig) {
            Write-Host "[config] Requested Config '$Config' differs from Preset '$presetConfig'. Using preset." -ForegroundColor Yellow
            $Config = $presetConfig
        } else {
            $Config = $presetConfig
        }
    }
} else {
    $Preset = "x64-Clang-$Config"
}

# Set up MSVC environment
$VS = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
$MSVC = Join-Path $VS "VC\Tools\MSVC\14.44.35207"
$root = "C:\Program Files (x86)\Windows Kits\10"
$latestSdk = "10.0.26100.0"

# Find LLVM/Clang
$LLVM = $null
if ($env:LLVM_HOME) {
    $cand = Join-Path $env:LLVM_HOME 'bin'
    if (Test-Path $cand) { $LLVM = $cand }
}
if (-not $LLVM) {
    $clangCmd = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
    if ($clangCmd) { $LLVM = (Split-Path -Parent $clangCmd.Path) }
}
if (-not $LLVM) {
    $llvmVs = (Join-Path $VS 'VC\Tools\Llvm\x64\bin')
    if (Test-Path $llvmVs) { $LLVM = $llvmVs }
}
if (-not $LLVM) {
    $llvmStd = 'C:\Program Files\LLVM\bin'
    if (Test-Path $llvmStd) { $LLVM = $llvmStd }
}
if (-not $LLVM) { 
    Write-Host "ERROR: No LLVM toolchain found." -ForegroundColor Red
    exit 1
}

Write-Host "Using LLVM from: $LLVM" -ForegroundColor Green
Write-Host "Build configuration: $Preset ($Config)" -ForegroundColor Cyan

# Normalize paths
$LLVM = $LLVM -replace '\\', '/'
$LLVM_CL = (Join-Path $LLVM 'clang-cl.exe') -replace '\\', '/'
$LLVM_LINK = (Join-Path $LLVM 'lld-link.exe') -replace '\\', '/'
$LLVM_LIB = (Join-Path $LLVM 'llvm-lib.exe') -replace '\\', '/'  # MSVC-compatible librarian
$LLVM_RANLIB = (Join-Path $LLVM 'llvm-ranlib.exe') -replace '\\', '/'
$RC = "$root\bin\$latestSdk\x64\rc.exe" -replace '\\', '/'
$LLVM_MT = (Join-Path $LLVM 'llvm-mt.exe') -replace '\\', '/'

# Build directory based on preset
$buildDir = "$Repo/out/build/$Preset"

# Helper function to preserve specific directories during clean
function Reset-BuildDirWithKeep {
    param(
        [Parameter(Mandatory = $true)][string]$BuildRoot,
        [string[]]$KeepRel = @(),
        [switch]$VerboseLog
    )

    # Temp staging area
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("mw05_keep_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null

    $kept = @()
    foreach ($rel in $KeepRel) {
        $src = Join-Path $BuildRoot $rel
        if (Test-Path -LiteralPath $src) {
            $dst = Join-Path $temp $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            if ($VerboseLog) {
                Write-Host "[Clean] Preserving $rel" -ForegroundColor DarkYellow
            }
            Move-Item -LiteralPath $src -Destination $dst -Force
            $kept += ,@($rel, $dst)
        } elseif ($VerboseLog) {
            Write-Host "[Clean] Not found (skip preserve): $rel" -ForegroundColor DarkGray
        }
    }

    # Wipe build root
    if (Test-Path -LiteralPath $BuildRoot) {
        Remove-Item -LiteralPath $BuildRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null

    # Restore preserved subtrees
    foreach ($pair in $kept) {
        $rel = $pair[0]; $dst = $pair[1]
        $restoreTarget = Join-Path $BuildRoot $rel
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $restoreTarget) | Out-Null
        Move-Item -LiteralPath $dst -Destination $restoreTarget -Force
        if ($VerboseLog) {
            Write-Host "[Clean] Restored $rel" -ForegroundColor DarkYellow
        }
    }

    # Cleanup temp
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

# Set up environment - THIS IS CRITICAL!
if (-not $env:MW05_ENV_INIT) {
    $env:INCLUDE = "$MSVC\include;$root\Include\$latestSdk\ucrt;$root\Include\$latestSdk\shared;$root\Include\$latestSdk\um;$root\Include\$latestSdk\winrt;$root\Include\$latestSdk\cppwinrt"
    $env:LIB = "$MSVC\lib\x64;$root\Lib\$latestSdk\ucrt\x64;$root\Lib\$latestSdk\um\x64"

    # Filter out MinGW from PATH to prevent CMake from finding the wrong ar.exe
    $pathEntries = $env:PATH -split ';' | Where-Object { $_ -notmatch 'mingw' }
    $env:PATH = "$LLVM;$MSVC\bin\Hostx64\x64;$root\bin\$latestSdk\x64;" + ($pathEntries -join ';')

    # CMake hints for Windows SDK
    $env:WindowsSdkDir = ($root -replace '\\', '/') + "/"
    $env:WindowsSDKVersion = "$latestSdk/"
    $env:CMAKE_SH = 'CMAKE_SH-NOTFOUND'

    $env:MW05_ENV_INIT = '1'

    Write-Host "Environment configured:" -ForegroundColor Cyan
    Write-Host "  INCLUDE: $($env:INCLUDE.Substring(0, [Math]::Min(100, $env:INCLUDE.Length)))..." -ForegroundColor DarkGray
    Write-Host "  LIB: $($env:LIB.Substring(0, [Math]::Min(100, $env:LIB.Length)))..." -ForegroundColor DarkGray
} else {
    Write-Host "[env] Using existing INCLUDE/LIB/PATH (MW05_ENV_INIT=1)" -ForegroundColor DarkGray
}

# Handle clean if requested
if ($Clean) {
    Write-Host "[Clean] Performing cleanup..." -ForegroundColor Yellow

    # Clean build directory but preserve game assets
    if (Test-Path $buildDir) {
        Reset-BuildDirWithKeep -BuildRoot $buildDir -KeepRel $KeepRel -VerboseLog
    }

    # Clean generated PPC sources
    $ppc = "$Repo/Mw05RecompLib/ppc"
    if (Test-Path $ppc) {
        Get-ChildItem -Path $ppc -Force -File -Filter 'ppc_recomp.*.cpp' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "[Clean] Removed generated PPC sources" -ForegroundColor DarkGray
    }

    # Clean patched XEX
    $patched = "$Repo/Mw05RecompLib/private/default_patched.xex"
    if (Test-Path $patched) {
        Remove-Item -Force $patched
        Write-Host "[Clean] Removed patched XEX" -ForegroundColor DarkGray
    }
}

if ($Action -eq 'configure' -or $Action -eq 'all') {
    # Bootstrap vcpkg if needed
    $VCPKG = "$Repo/thirdparty/vcpkg"
    $vcpkgExe = Join-Path $VCPKG "vcpkg.exe"
    if (-not (Test-Path $vcpkgExe)) {
        Write-Host "Bootstrapping vcpkg..." -ForegroundColor Yellow
        $env:VCPKG_ROOT = $VCPKG
        & "$VCPKG/bootstrap-vcpkg.bat"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed to bootstrap vcpkg!" -ForegroundColor Red
            exit 1
        }
    }

    # Install vcpkg dependencies
    Write-Host "Installing vcpkg dependencies..." -ForegroundColor Yellow
    & "$vcpkgExe" install --triplet x64-windows-static --host-triplet x64-windows-static `
        --x-install-root="$buildDir/vcpkg_installed"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to install vcpkg dependencies!" -ForegroundColor Red
        exit 1
    }

    # Configure
    Write-Host "Configuring CMake with preset: $Preset" -ForegroundColor Cyan

    $freshArgs = @()
    if ($Clean) {
        $freshArgs += '--fresh'
    }

    cmake --preset $Preset @freshArgs `
      -DCMAKE_C_COMPILER:FILEPATH="$LLVM_CL" `
      -DCMAKE_CXX_COMPILER:FILEPATH="$LLVM_CL" `
      -DCMAKE_LINKER:FILEPATH="$LLVM_LINK" `
      -DCMAKE_AR:FILEPATH="$LLVM_LIB" `
      -DCMAKE_RANLIB:FILEPATH="$LLVM_RANLIB" `
      -DCMAKE_RC_COMPILER:FILEPATH="$RC" `
      -DCMAKE_MT:FILEPATH="$LLVM_MT" `
      "-DCMAKE_BUILD_TYPE=$Config" `
      -DCMAKE_TOOLCHAIN_FILE="$VCPKG/scripts/buildsystems/vcpkg.cmake" `
      -DVCPKG_TARGET_TRIPLET=x64-windows-static `
      -DVCPKG_HOST_TRIPLET=x64-windows-static `
      -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON `
      -DCMAKE_PREFIX_PATH="$VCPKG_INST;$VCPKG_INST/share;$VCPKG_INST/lib/cmake" `
      -DFreetype_DIR="$VCPKG_INST/share/freetype" `
      -DFREETYPE_LIBRARY="$VCPKG_INST/lib/freetype.lib" `
      -DFREETYPE_INCLUDE_DIRS="$VCPKG_INST/include" `
      -DCMAKE_SYSTEM_VERSION="$latestSdk" `
      -DCMAKE_SH=CMAKE_SH-NOTFOUND `
      -DMW05_RECOMP_SKIP_CODEGEN=OFF `
      -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF `
      -DMW05_GEN_INDIRECT_REDIRECTS=OFF `
      -DMW05_GEN_INDIRECT_REDIRECTS_HARDFIX=OFF

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Configuration failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

if ($Action -eq 'build' -or $Action -eq 'all') {
    Write-Host "Building Mw05Recomp..." -ForegroundColor Cyan

    # Build with environment already set
    cmake --build $buildDir --target Mw05Recomp -j

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nBuild successful!" -ForegroundColor Green
        $exe = "$buildDir/Mw05Recomp/Mw05Recomp.exe"
        if (Test-Path $exe) {
            Write-Host "Executable: $exe" -ForegroundColor Cyan
        }
    } else {
        Write-Host "`nBuild failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

