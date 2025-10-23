# Windows Clang Toolchain - matches build_cmd.ps1 environment setup

# Find LLVM (same priority as build_cmd.ps1)
set(LLVM_CANDIDATES "")
if(DEFINED ENV{LLVM_HOME})
    list(APPEND LLVM_CANDIDATES "$ENV{LLVM_HOME}/bin")
endif()
list(APPEND LLVM_CANDIDATES
    "C:/Program Files/LLVM/bin"
    "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/Llvm/x64/bin"
)

set(LLVM_BIN "")
foreach(CANDIDATE ${LLVM_CANDIDATES})
    if(EXISTS "${CANDIDATE}/clang-cl.exe")
        set(LLVM_BIN "${CANDIDATE}")
        message(STATUS "Using LLVM: ${LLVM_BIN}")
        break()
    endif()
endforeach()

if(NOT LLVM_BIN)
    message(FATAL_ERROR "No LLVM found. Set LLVM_HOME or install LLVM.")
endif()

# Windows SDK and MSVC paths (same as build_cmd.ps1)
set(WINSDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
set(WINSDK_VERSION "10.0.26100.0")
set(VS_ROOT "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools")
set(MSVC_VERSION "14.44.35207")
set(MSVC_ROOT "${VS_ROOT}/VC/Tools/MSVC/${MSVC_VERSION}")

# Set compilers
set(CMAKE_C_COMPILER "${LLVM_BIN}/clang-cl.exe" CACHE FILEPATH "C compiler" FORCE)
set(CMAKE_CXX_COMPILER "${LLVM_BIN}/clang-cl.exe" CACHE FILEPATH "C++ compiler" FORCE)
# Use MSVC link.exe to avoid lld-link flag incompatibilities
set(CMAKE_LINKER "${MSVC_ROOT}/bin/Hostx64/x64/link.exe" CACHE FILEPATH "Linker" FORCE)
set(CMAKE_RC_COMPILER "${WINSDK_ROOT}/bin/${WINSDK_VERSION}/x64/rc.exe" CACHE FILEPATH "RC" FORCE)
set(CMAKE_MT "${WINSDK_ROOT}/bin/${WINSDK_VERSION}/x64/mt.exe" CACHE FILEPATH "MT" FORCE)

# Include directories
include_directories(SYSTEM
    "${MSVC_ROOT}/include"
    "${WINSDK_ROOT}/Include/${WINSDK_VERSION}/ucrt"
    "${WINSDK_ROOT}/Include/${WINSDK_VERSION}/shared"
    "${WINSDK_ROOT}/Include/${WINSDK_VERSION}/um"
    "${WINSDK_ROOT}/Include/${WINSDK_VERSION}/winrt"
    "${WINSDK_ROOT}/Include/${WINSDK_VERSION}/cppwinrt"
)

# Library directories
link_directories(
    "${MSVC_ROOT}/lib/x64"
    "${WINSDK_ROOT}/Lib/${WINSDK_VERSION}/ucrt/x64"
    "${WINSDK_ROOT}/Lib/${WINSDK_VERSION}/um/x64"
)

# Fix lld-link incompatibilities
set(CMAKE_EXE_LINKER_FLAGS_INIT "/INCREMENTAL:NO" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_INIT "/INCREMENTAL:NO" CACHE STRING "" FORCE)
# Help CMake find Windows SDK libraries
set(CMAKE_LIBRARY_PATH
    "${MSVC_ROOT}/lib/x64"
    "${WINSDK_ROOT}/Lib/${WINSDK_VERSION}/ucrt/x64"
    "${WINSDK_ROOT}/Lib/${WINSDK_VERSION}/um/x64"
    CACHE STRING "Library search path" FORCE)

# Also set common environment vars used by find scripts
set(ENV{WindowsSdkDir} "${WINSDK_ROOT}")
set(ENV{WindowsSDKLibVersion} "${WINSDK_VERSION}\\")
set(ENV{VCToolsInstallDir} "${MSVC_ROOT}\\")

set(CMAKE_MODULE_LINKER_FLAGS_INIT "/INCREMENTAL:NO" CACHE STRING "" FORCE)

