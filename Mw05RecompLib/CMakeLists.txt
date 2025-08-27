project("Mw05RecompLib")

add_compile_options(-fno-strict-aliasing)
if (WIN32)
  add_compile_options(/fp:strict)
else()
  add_compile_options(-ffp-model=strict)
endif()

# ---- Configurable resources root -------------------------------------------
set(MW05_RECOMP_RESOURCES_ROOT
    "${CMAKE_SOURCE_DIR}/../MW05RecompResources"
    CACHE PATH "Path to external resources repo")

# Fail early with a clear message if required resource is missing
# if(NOT EXISTS "${MW05_RECOMP_RESOURCES_ROOT}/shaders/shader.ar")
#   message(FATAL_ERROR
#     "Missing shader.ar at ${MW05_RECOMP_RESOURCES_ROOT}/shaders/shader.ar.\n"
#     "Make sure MW05RecompResources is checked out and Git LFS data is pulled.")
# endif()

# ---- Tools & paths ---------------------------------------------------------
# Ensure tool subprojects are added somewhere (usually in top-level CMake).
# add_subdirectory("${MW05_RECOMP_TOOLS_ROOT}/XenonRecomp")
# add_subdirectory("${MW05_RECOMP_TOOLS_ROOT}/XenosRecomp")

# Only set compile defs on the tool targets if they actually exist:
if (TARGET XenonRecomp)
  target_compile_definitions(XenonRecomp PRIVATE 
    XENON_RECOMP_CONFIG_FILE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/config/SWA.toml"
    XENON_RECOMP_HEADER_FILE_PATH="${MW05_RECOMP_TOOLS_ROOT}/XenonRecomp/XenonUtils/ppc_context.h"
  )
endif()

set(XENOS_RECOMP_ROOT    "${MW05_RECOMP_TOOLS_ROOT}/XenosRecomp/XenosRecomp")
set(XENOS_RECOMP_INCLUDE "${XENOS_RECOMP_ROOT}/shader_common.h")

if (TARGET XenosRecomp)
  target_compile_definitions(XenosRecomp PRIVATE
    XENOS_RECOMP_INPUT="${CMAKE_CURRENT_SOURCE_DIR}/private"
    XENOS_RECOMP_OUTPUT="${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
    XENOS_RECOMP_INCLUDE_INPUT="${XENOS_RECOMP_INCLUDE}"
    MW05_RECOMP
  )
endif()

# Make sure output dirs exist (since we write into source tree)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/private")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/shader")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ppc")

# ---- Generated sources -----------------------------------------------------
set(MW05_RECOMP_PPC_RECOMPILED_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_config.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_context.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_func_mapping.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp_shared.h"
)
foreach(i RANGE 0 260)
  list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp.${i}.cpp")
endforeach()

# 1) Patch default.xex + generate PPC .cpp files
add_custom_command(
  OUTPUT
    "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
    ${MW05_RECOMP_PPC_RECOMPILED_SOURCES}
  COMMAND "$<TARGET_FILE:XenonRecomp>"
  # Run from repo root so the tool's internal relative paths match expectations.
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  DEPENDS
    "$<TARGET_FILE:XenonRecomp>"
    "${CMAKE_CURRENT_SOURCE_DIR}/private/default.xex"
    "${CMAKE_CURRENT_SOURCE_DIR}/private/default.xexp"
    "${CMAKE_CURRENT_SOURCE_DIR}/config/SWA.toml"
  BYPRODUCTS
    "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
    ${MW05_RECOMP_PPC_RECOMPILED_SOURCES}
  USES_TERMINAL
)

# 2) Decompress shaders (read shader.ar from resources repo)
# add_custom_command(
#   OUTPUT
#     "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
#   COMMAND "$<TARGET_FILE:x_decompress>"
#           "${MW05_RECOMP_RESOURCES_ROOT}/shaders/shader.ar"
#           "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
#   WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
#   DEPENDS
#     "$<TARGET_FILE:x_decompress>"
#     "${MW05_RECOMP_RESOURCES_ROOT}/shaders/shader.ar"
#   BYPRODUCTS
#     "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
#   USES_TERMINAL
# )

# Gather Xenos sources for dependency tracking
file(GLOB XENOS_RECOMP_SOURCES
  "${XENOS_RECOMP_ROOT}/*.h"
  "${XENOS_RECOMP_ROOT}/*.cpp"
)

# 3) Build shader cache (runs after 1 & 2)
add_custom_command(
  OUTPUT
    "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
  COMMAND "$<TARGET_FILE:XenosRecomp>"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  DEPENDS
    "$<TARGET_FILE:XenosRecomp>"
    "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
    "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
    ${XENOS_RECOMP_SOURCES}
    "${XENOS_RECOMP_INCLUDE}"
  BYPRODUCTS
    "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
  USES_TERMINAL
)

# Final library
add_library(Mw05RecompLib
  ${MW05_RECOMP_PPC_RECOMPILED_SOURCES}
  "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
)

# Ensure the library waits for generators
add_dependencies(Mw05RecompLib
  XenonRecomp
  x_decompress
  XenosRecomp
)

target_include_directories(Mw05RecompLib PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(Mw05RecompLib PRIVATE "${MW05_RECOMP_TOOLS_ROOT}/XenonRecomp/thirdparty/simde")
target_precompile_headers(Mw05RecompLib PUBLIC   "ppc/ppc_recomp_shared.h")
