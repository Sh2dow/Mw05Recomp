cmake_minimum_required (VERSION 3.20)

# Try to infer VCPKG_ROOT if the toolchain file points to vcpkg
if(NOT DEFINED ENV{VCPKG_ROOT})
  if(DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg.cmake")
    get_filename_component(_vcpkg_bs "${CMAKE_TOOLCHAIN_FILE}" DIRECTORY)        # .../scripts/buildsystems
    get_filename_component(_vcpkg_root "${_vcpkg_bs}/../.." ABSOLUTE)
    set(ENV{VCPKG_ROOT} "${_vcpkg_root}")
  endif()
endif()

if(NOT DEFINED ENV{VCPKG_ROOT})
  message(FATAL_ERROR "VCPKG_ROOT is not defined! Set it or pass -DCMAKE_TOOLCHAIN_FILE=<...>/vcpkg.cmake")
endif()

set(MW05_RECOMP_THIRDPARTY_ROOT ${CMAKE_SOURCE_DIR}/thirdparty)
set(MW05_RECOMP_TOOLS_ROOT ${CMAKE_SOURCE_DIR}/tools)
set(CMAKE_CXX_STANDARD 20)
set(BUILD_SHARED_LIBS OFF)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project("Mw05Recomp-ALL")

if (APPLE)
    enable_language(OBJC OBJCXX)
endif()

if (CMAKE_OSX_ARCHITECTURES)
    set(MW05_RECOMP_ARCHITECTURE ${CMAKE_OSX_ARCHITECTURES})
elseif(CMAKE_SYSTEM_PROCESSOR)
    set(MW05_RECOMP_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
else()
    set(MW05_RECOMP_ARCHITECTURE ${CMAKE_HOST_SYSTEM_PROCESSOR})
endif()
string(TOLOWER "${MW05_RECOMP_ARCHITECTURE}" MW05_RECOMP_ARCHITECTURE)
message(STATUS "Detected architecture: ${MW05_RECOMP_ARCHITECTURE}")

if (MW05_RECOMP_ARCHITECTURE STREQUAL "x86_64" OR MW05_RECOMP_ARCHITECTURE STREQUAL "amd64")
    # Target Sandy Bridge for all projects
    add_compile_options(
        -march=sandybridge
    )
endif()

add_subdirectory(${MW05_RECOMP_THIRDPARTY_ROOT})
add_subdirectory(${MW05_RECOMP_TOOLS_ROOT})

# Include sub-projects.
add_subdirectory("Mw05RecompLib")
add_subdirectory("Mw05Recomp")
