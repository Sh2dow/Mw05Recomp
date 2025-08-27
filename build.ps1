# Load VS env (keep as you had)
& "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=x64 | Out-Null

# Resolve Kits root
$kitsRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10

# Pick the newest *numeric* SDK folder under ...\Lib (ignore 'wdf', etc.)
$latestSdk = Get-ChildItem "$kitsRoot\Lib" -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object Name -Descending |
    Select-Object -First 1 -ExpandProperty Name

if (-not $latestSdk) {
    throw "No Windows 10/11 SDK found under '$kitsRoot\Lib'. Install one via Visual Studio Installer."
}

# Build the path to d3d12.lib
$d3d12 = Join-Path $kitsRoot "Lib\$latestSdk\um\x64\d3d12.lib"
if (-not (Test-Path $d3d12)) {
    throw "d3d12.lib not found at: $d3d12 (SDK corrupt?). Reinstall Windows 10/11 SDK."
}

Write-Host "Using SDK: $latestSdk"
Write-Host "D3D12_LIB: $d3d12"

# Clean previous failed cache
Remove-Item -Recurse -Force out/build/msvc-release -ErrorAction SilentlyContinue

$toolchain = "D:/Repos/Games/MW05Recomp/thirdparty/vcpkg/scripts/buildsystems/vcpkg.cmake"

cmake -S . -B out/build/msvc-release `
  -G "Visual Studio 17 2022" -A x64 -T ClangCL `
  -DCMAKE_TOOLCHAIN_FILE="$toolchain" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DD3D12_LIB="$d3d12" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_SYSTEM_VERSION=$latestSdk `
  -DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION=$latestSdk

cmake --build out/build/msvc-release --config Release


# open x64 Clang Debug (uses Ninja, clang-cl, lld-link, and VCPKG_ROOT from preset)
#cmake --preset x64-Clang-Release
#cmake --build out/build/x64-Clang-Release
