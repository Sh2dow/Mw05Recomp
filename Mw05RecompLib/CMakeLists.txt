project("Mw05RecompLib")

add_compile_options(
    -fno-strict-aliasing
)

if (WIN32)
    add_compile_options(/fp:strict)
else()
    add_compile_options(-ffp-model=strict)
endif()

# Allow overriding XenonRecomp config/header paths from cache or CLI
set(XENON_RECOMP_CONFIG_FILE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/config/MW05.toml" CACHE STRING "Path to XenonRecomp config TOML")
set(XENON_RECOMP_HEADER_FILE_PATH "${MW05_RECOMP_TOOLS_ROOT}/XenonRecomp/XenonUtils/ppc_context.h" CACHE STRING "Path to XenonRecomp ppc_context.h for codegen")

target_compile_definitions(XenonRecomp PRIVATE 
    XENON_RECOMP_CONFIG_FILE_PATH=\"${XENON_RECOMP_CONFIG_FILE_PATH}\"
    XENON_RECOMP_HEADER_FILE_PATH=\"${XENON_RECOMP_HEADER_FILE_PATH}\")

set(MW05_RECOMP_PPC_RECOMPILED_SOURCES 
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_config.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_context.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp_shared.h"
)

# Prefer a generated file list if present (created by bootstrap step)
set(_MW05_PPC_LIST "${CMAKE_CURRENT_SOURCE_DIR}/ppc/generated_sources.cmake")
if (EXISTS ${_MW05_PPC_LIST})
    include(${_MW05_PPC_LIST})
    # Filter out any stale entries that no longer exist on disk
    set(_MW05_PPC_FILTERED)
    foreach(_f IN LISTS MW05_RECOMP_PPC_RECOMPILED_SOURCES)
        if (EXISTS "${_f}")
            list(APPEND _MW05_PPC_FILTERED "${_f}")
        endif()
    endforeach()
    set(MW05_RECOMP_PPC_RECOMPILED_SOURCES ${_MW05_PPC_FILTERED})
    # If the generated list was stale/empty, fall back to bootstrap stub
    list(LENGTH MW05_RECOMP_PPC_RECOMPILED_SOURCES _ppc_len)
    if (_ppc_len EQUAL 0)
        list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_bootstrap_stub.cpp")
    endif()
    # Ensure mapping table TU is included even when using generated list
    list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_func_mapping.cpp")
else()
    # No generated list. If there are already generated files in-tree, use them.
    file(GLOB _ppc_existing "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_recomp.*.cpp")
    list(LENGTH _ppc_existing _ppc_existing_len)
    if (_ppc_existing_len GREATER 0)
        list(SORT _ppc_existing)
        list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES ${_ppc_existing})
    else()
        # Bootstrap: include a tiny stub so CMake can configure without generated sources.
        list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_bootstrap_stub.cpp")
    endif()
    list(APPEND MW05_RECOMP_PPC_RECOMPILED_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/ppc/ppc_func_mapping.cpp")
endif()

add_custom_command(
    OUTPUT 
        "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
    COMMAND 
        $<TARGET_FILE:XenonRecomp>
    DEPENDS 
        "${CMAKE_CURRENT_SOURCE_DIR}/private/default.xex"
        #"${CMAKE_CURRENT_SOURCE_DIR}/private/default.xexp"
        "${CMAKE_CURRENT_SOURCE_DIR}/config/MW05.toml"
    USES_TERMINAL
)

# Expose a phony target to trigger code generation explicitly
add_custom_target(PPCCodegen
    DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
)

# add_custom_command(
#     OUTPUT
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
#     COMMAND
#         $<TARGET_FILE:x_decompress> "${CMAKE_CURRENT_SOURCE_DIR}/private/shader.ar" "${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar"
#     DEPENDS
#         "${CMAKE_CURRENT_SOURCE_DIR}/private/shader.ar"
# )

set(XENOS_RECOMP_ROOT "${MW05_RECOMP_TOOLS_ROOT}/XenosRecomp/XenosRecomp")
set(XENOS_RECOMP_INCLUDE "${XENOS_RECOMP_ROOT}/shader_common.h")

target_compile_definitions(XenosRecomp PRIVATE 
    XENOS_RECOMP_INPUT=\"${CMAKE_CURRENT_SOURCE_DIR}/private\" 
    XENOS_RECOMP_OUTPUT=\"${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp\"
    XENOS_RECOMP_INCLUDE_INPUT=\"${XENOS_RECOMP_INCLUDE}\"
    MW05_RECOMP
)

file(GLOB XENOS_RECOMP_SOURCES 
    "${XENOS_RECOMP_ROOT}/*.h"
    "${XENOS_RECOMP_ROOT}/*.cpp"
)

add_custom_command(
    OUTPUT 
        "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp"
    COMMAND
        $<TARGET_FILE:XenosRecomp>
    DEPENDS 
        "${CMAKE_CURRENT_SOURCE_DIR}/private/default_patched.xex"
        #"${CMAKE_CURRENT_SOURCE_DIR}/private/shader_decompressed.ar" 
        ${XENOS_RECOMP_SOURCES} 
        ${XENOS_RECOMP_INCLUDE}
    USES_TERMINAL
)

# Shader cache is generated later; include it only if present to avoid configure failures.
set(MW05_SHADER_SOURCES "shader/shader_cache.h")
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/shader/shader_cache.cpp")
    list(APPEND MW05_SHADER_SOURCES "shader/shader_cache.cpp")
endif()

add_library(Mw05RecompLib 
    ${MW05_RECOMP_PPC_RECOMPILED_SOURCES}
    ${MW05_SHADER_SOURCES}
)

# Ensure the library build orders after codegen when invoked together
add_dependencies(Mw05RecompLib PPCCodegen)

target_include_directories(Mw05RecompLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(Mw05RecompLib PRIVATE "${MW05_RECOMP_TOOLS_ROOT}/XenonRecomp/thirdparty/simde")
target_compile_definitions(Mw05RecompLib PRIVATE _CRT_SECURE_NO_WARNINGS)
target_precompile_headers(Mw05RecompLib PUBLIC "ppc/ppc_recomp_shared.h")
# Enable SSSE3 for generated PPC recompiler TUs that use _mm_shuffle_epi8
# Build Mw05RecompLib with SSSE3 so PCH and all TUs share the same target features
target_compile_options(Mw05RecompLib PRIVATE
    -mssse3 -msse4.1
    -mavx -mavx2 -mfma
    -mbmi -mbmi2 -mpopcnt -mlzcnt)
