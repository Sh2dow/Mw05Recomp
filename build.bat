cmake -S . -B build ^
  -G "Visual Studio 17 2022" ^
  -T ClangCL ^
  -A x64 ^
  -DCMAKE_BUILD_TYPE=Release
  -DUSE_VCPKG=OFF
