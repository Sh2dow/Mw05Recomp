param(
    [ValidateSet("MSVC","Clang")]
    [string]$Compiler = "MSVC",

    [ValidateSet("x64","x86")]
    [string]$Arch = "x64",

    [ValidateSet("Debug","Release","RelWithDebInfo","MinSizeRel")]
    [string]$Config = "Debug",

    [switch]$Clean,

    # Path to source (CMakeLists.txt root)
    [string]$Src = ".",

    # Root folder for all build directories
    [string]$BuildRoot = "build",

    # Extra args forwarded to CMake configure step (e.g. '-DUSE_IMGUI=ON')
    [string[]]$CMakeArgs = @(),

    # Optional explicit generator (e.g. 'Ninja', 'Visual Studio 17 2022')
    [string]$Generator = ""
)

$ErrorActionPreference = "Stop"

function Test-Exe([string]$name) {
    try { return [bool](Get-Command $name -ErrorAction Stop) } catch { return $false }
}

# Decide generator: prefer explicit, else Ninja if available, else leave empty (CMake default)
$DetectedGenerator = $Generator
if (-not $DetectedGenerator) {
    if (Test-Exe "ninja") {
        $DetectedGenerator = "Ninja"
    } else {
        $DetectedGenerator = ""  # Let CMake pick a Visual Studio generator if in a Dev shell
    }
}

# Build dir name like build/msvc-x64-Debug or build/clang-x86-Release
$compilerKey = if ($Compiler -eq "Clang") { "clang" } else { "msvc" }
$Bld = Join-Path $BuildRoot "$compilerKey-$Arch-$Config"

if ($Clean -and (Test-Path $Bld)) {
    Write-Host "Cleaning $Bld ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $Bld
}

# Ensure build dir exists
New-Item -ItemType Directory -Force -Path $Bld | Out-Null

# Compose CMake configure args
$configureArgs = @()
if ($DetectedGenerator) {
    $configureArgs += @("-G", $DetectedGenerator)
}

# For Visual Studio generators, pass -A to set architecture
$visualStudioGenerators = @(
    "Visual Studio 17 2022",
    "Visual Studio 16 2019",
    "Visual Studio 15 2017",
    "Visual Studio 14 2015"
)
$IsVsGen = $visualStudioGenerators -contains $DetectedGenerator

if ($IsVsGen) {
    $cmakeArch = if ($Arch -eq "x86") { "Win32" } else { "x64" }
    $configureArgs += @("-A", $cmakeArch)
}

# Compiler toolset selection
if ($Compiler -eq "Clang") {
    # Prefer clang-cl toolset on Windows so we stay ABI-compatible with MSVC
    # Works with VS and Ninja; with VS generator we can use -T ClangCL.
    if ($IsVsGen) {
        $configureArgs += @("-T", "ClangCL")
    } else {
        # For single-config generators like Ninja, explicitly set compilers
        $configureArgs += @("-DCMAKE_C_COMPILER=clang-cl", "-DCMAKE_CXX_COMPILER=clang-cl")
    }
} else {
    # MSVC: if using Ninja, make sure we point at cl.exe
    if (-not $IsVsGen -and -not (Test-Exe "cl")) {
        Write-Warning "MSVC selected with a single-config generator, but 'cl.exe' is not in PATH. Consider running from a 'Developer PowerShell for VS'."
    }
}

# Configuration type
# For single-config generators (e.g. Ninja), use CMAKE_BUILD_TYPE.
# For VS multi-config, omit here and supply --config during build.
$SingleConfigGenerators = @("Ninja", "NMake Makefiles", "Unix Makefiles")
$IsSingleConfig = $SingleConfigGenerators -contains $DetectedGenerator
if ($IsSingleConfig) {
    $configureArgs += @("-DCMAKE_BUILD_TYPE=$Config")
}

# Add user-provided extra CMake args
if ($CMakeArgs.Count -gt 0) {
    $configureArgs += $CMakeArgs
}

Write-Host "== Configure ==" -ForegroundColor Cyan
Write-Host "cmake -S `"$Src`" -B `"$Bld`" $($configureArgs -join ' ')" -ForegroundColor DarkGray
cmake -S "$Src" -B "$Bld" @configureArgs

Write-Host "`n== Build ==" -ForegroundColor Cyan
$buildArgs = @("--build", "$Bld")
if (-not $IsSingleConfig) {
    $buildArgs += @("--config", $Config)
}
# Add parallel jobs if supported by CMake (CMake 3.12+)
$buildArgs += @("--parallel")

Write-Host "cmake $($buildArgs -join ' ')" -ForegroundColor DarkGray
cmake @buildArgs

Write-Host "`n✅ Build completed for $Compiler / $Arch / $Config in '$Bld'." -ForegroundColor Green
