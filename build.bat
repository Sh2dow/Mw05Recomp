cmake -S . -B build_vs -G "Visual Studio 17 2022" -A x64 -T ClangCL
cmake --build build_vs --config Release