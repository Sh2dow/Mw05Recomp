project("Mw05Recomp")

if (WIN32)
    option(MW05_RECOMP_D3D12 "Add D3D12 support for rendering" ON)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    option(MW05_RECOMP_FLATPAK "Configure the build for Flatpak compatibility." OFF)
endif()

function(BIN2C)
    cmake_parse_arguments(BIN2C_ARGS "" "TARGET_OBJ;SOURCE_FILE;DEST_FILE;ARRAY_NAME;COMPRESSION_TYPE" "" ${ARGN})

    if(NOT BIN2C_ARGS_TARGET_OBJ)
        message(FATAL_ERROR "TARGET_OBJ not specified.")
    endif()

    if(NOT BIN2C_ARGS_SOURCE_FILE)
        message(FATAL_ERROR "SOURCE_FILE not specified.")
    endif()

    if(NOT BIN2C_ARGS_DEST_FILE)
        set(BIN2C_ARGS_DEST_FILE "${BIN2C_ARGS_SOURCE_FILE}")
    endif()

    if(NOT BIN2C_ARGS_COMPRESSION_TYPE)
        set(BIN2C_ARGS_COMPRESSION_TYPE "none")
    endif()

    add_custom_command(OUTPUT "${BIN2C_ARGS_DEST_FILE}.c"
        COMMAND $<TARGET_FILE:file_to_c> "${BIN2C_ARGS_SOURCE_FILE}" "${BIN2C_ARGS_ARRAY_NAME}" "${BIN2C_ARGS_COMPRESSION_TYPE}" "${BIN2C_ARGS_DEST_FILE}.c" "${BIN2C_ARGS_DEST_FILE}.h"
        DEPENDS "${BIN2C_ARGS_SOURCE_FILE}"
        BYPRODUCTS "${BIN2C_ARGS_DEST_FILE}.h"
        COMMENT "Generating binary header for ${BIN2C_ARGS_SOURCE_FILE}..."
    )

    set_source_files_properties(${BIN2C_ARGS_DEST_FILE}.c PROPERTIES SKIP_PRECOMPILE_HEADERS ON)
    target_sources(${BIN2C_ARGS_TARGET_OBJ} PRIVATE ${BIN2C_ARGS_DEST_FILE}.c)
endfunction()

add_compile_options(
    -fno-strict-aliasing
    -Wno-switch
    -Wno-unused-function
    -Wno-unused-variable
    -Wno-unused-but-set-variable
    -Wno-void-pointer-to-int-cast
    -Wno-int-to-void-pointer-cast
    -Wno-invalid-offsetof
    -Wno-null-arithmetic
    -Wno-null-conversion
    -Wno-tautological-undefined-compare
)

if (WIN32)
    add_compile_options(/fp:strict)
else()
    add_compile_options(-ffp-model=strict)
endif()

# Title/module name to load at runtime (can be overridden for other games)
set(MW05_MODULE_NAME "default_patched.xex" CACHE STRING "Module filename to load at runtime")
add_compile_definitions(MW05_MODULE_NAME="${MW05_MODULE_NAME}")

add_compile_definitions(
    SDL_MAIN_HANDLED
    _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR # Microsoft wtf?
    _CRT_SECURE_NO_WARNINGS)

set(MW05_RECOMP_PRECOMPILED_HEADERS
    "stdafx.h"
)

set(MW05_RECOMP_KERNEL_CXX_SOURCES
    "kernel/imports.cpp"
    "kernel/xdm.cpp"
    "kernel/heap.cpp"
    "kernel/memory.cpp"
    "kernel/trace.cpp"
    "kernel/vm_arena.cpp"
    "kernel/xam.cpp"
    "kernel/io/file_system.cpp"
)

set(MW05_RECOMP_LOCALE_CXX_SOURCES
    "locale/config_locale.cpp"
    "locale/locale.cpp"
)

if (WIN32)
    set(MW05_RECOMP_OS_CXX_SOURCES
        "os/win32/logger_win32.cpp"
        "os/win32/media_win32.cpp"
        "os/win32/process_win32.cpp"
        "os/win32/user_win32.cpp"
        "os/win32/version_win32.cpp"
    )
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(MW05_RECOMP_OS_CXX_SOURCES
        "os/linux/logger_linux.cpp"
        "os/linux/media_linux.cpp"
        "os/linux/process_linux.cpp"
        "os/linux/user_linux.cpp"
        "os/linux/version_linux.cpp"
    )
elseif (APPLE)
    set(MW05_RECOMP_OS_CXX_SOURCES
        "os/macos/logger_macos.cpp"
        "os/macos/media_macos.cpp"
        "os/macos/process_macos.cpp"
        "os/macos/user_macos.cpp"
        "os/macos/version_macos.cpp"
    )
endif()

set(MW05_RECOMP_CPU_CXX_SOURCES
    "cpu/guest_thread.cpp"
    "cpu/mw05_boot_shims.cpp"
    "cpu/mw05_trace_threads.cpp"
    "cpu/ppc_list_shims.cpp"
    "cpu/mw05_scheduler_shims.cpp"
    "cpu/mw05_loader_shims.cpp"
    "cpu/mw05_streaming_bridge.cpp"
)

set(MW05_RECOMP_GPU_CXX_SOURCES
    "gpu/video.cpp"
    "gpu/imgui/imgui_common.cpp"
    "gpu/imgui/imgui_snapshot.cpp"
    "gpu/mw05_trace_shims.cpp"
    "gpu/mw05_draw_diagnostic.cpp"
    "gpu/mw05_micro_interpreter.cpp"
    "gpu/pm4_parser.cpp"
)

set(MW05_RECOMP_APU_CXX_SOURCES
    "apu/audio.cpp"
    "apu/embedded_player.cpp"
    "apu/driver/sdl_driver.cpp"
)

set(MW05_RECOMP_HID_CXX_SOURCES
    "hid/hid.cpp"
    "hid/driver/sdl_hid.cpp"
)

# Optional SWA/Hedgehog integration (off by default)
option(MW05_ENABLE_SWA "Enable SWA/Hedgehog API bindings" OFF)

# Patches compiled in this app
set(MW05_RECOMP_PATCHES_CXX_SOURCES
    "patches/inspire_patches.cpp"
)
if (MW05_ENABLE_SWA)
    list(APPEND MW05_RECOMP_PATCHES_CXX_SOURCES
        "patches/aspect_ratio_patches.cpp"
    )
endif()

set(MW05_RECOMP_UI_CXX_SOURCES
    "ui/achievement_overlay.cpp"
    "ui/achievement_menu_stub.cpp"
    "ui/black_bar.cpp"
    "ui/button_guide.cpp"
    "ui/fader.cpp"
    "ui/game_window.cpp"
    "ui/imgui_utils.cpp"
    "ui/installer_wizard.cpp"
    "ui/message_window_stub.cpp"
    "ui/options_menu_stub.cpp"
    "ui/tv_static.cpp"
)

option(MW05_ENABLE_INSTALLER "Build the installer wizard UI" OFF)
if (MW05_ENABLE_INSTALLER)
    add_compile_definitions(MW05_ENABLE_INSTALLER)
    set(MW05_RECOMP_INSTALL_CXX_SOURCES
        "install/installer.cpp"
        "install/iso_file_system.cpp"
        "install/update_checker.cpp"
        "install/xcontent_file_system.cpp"
        "install/hashes/apotos_shamar.cpp"
        "install/hashes/chunnan.cpp"
        "install/hashes/empire_city_adabat.cpp"
        "install/hashes/game.cpp"
        "install/hashes/holoska.cpp"
        "install/hashes/mazuri.cpp"
        "install/hashes/spagonia.cpp"
        "install/hashes/update.cpp"
    )
else()
    set(MW05_RECOMP_INSTALL_CXX_SOURCES)
endif()

set(MW05_RECOMP_USER_CXX_SOURCES
    "user/achievement_data.cpp"
    "user/achievement_manager.cpp"
    "user/config.cpp"
    "user/registry.cpp"
    "user/paths.cpp"
    "user/persistent_data.cpp"
    "user/persistent_storage_manager.cpp"
)

# Disable Unleashed-specific mod loader
set(MW05_RECOMP_MOD_CXX_SOURCES)

# Use the SDL3 backend for ImGui
# (Just list the correct file; don't try list(REMOVE_ITEM) inside set())
option(MW05_ENABLE_IMPLOT "Build ImPlot support" OFF)
option(MW05_ENABLE_UNLEASHED "Enable Unleashed/SWA integration" OFF)
set(MW05_RECOMP_THIRDPARTY_SOURCES
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui/backends/imgui_impl_sdl3.cpp"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui/imgui.cpp"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui/imgui_draw.cpp"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui/imgui_tables.cpp"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui/imgui_widgets.cpp"
    "${MW05_RECOMP_TOOLS_ROOT}/XenosRecomp/thirdparty/smol-v/source/smolv.cpp"
)
if (MW05_ENABLE_IMPLOT)
    list(APPEND MW05_RECOMP_THIRDPARTY_SOURCES
        "${MW05_RECOMP_THIRDPARTY_ROOT}/implot/implot.cpp"
        "${MW05_RECOMP_THIRDPARTY_ROOT}/implot/implot_demo.cpp"
        "${MW05_RECOMP_THIRDPARTY_ROOT}/implot/implot_items.cpp")
endif()

set(MW05_RECOMP_THIRDPARTY_INCLUDES
    "${MW05_RECOMP_THIRDPARTY_ROOT}/concurrentqueue"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/ddspp"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/imgui"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/json/include"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/magic_enum/include"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/stb"
    "${MW05_RECOMP_THIRDPARTY_ROOT}/unordered_dense/include"
    "${MW05_RECOMP_TOOLS_ROOT}/bc_diff"
    "${MW05_RECOMP_TOOLS_ROOT}/XenosRecomp/thirdparty/smol-v/source"
)
if (MW05_ENABLE_IMPLOT)
    list(APPEND MW05_RECOMP_THIRDPARTY_INCLUDES "${MW05_RECOMP_THIRDPARTY_ROOT}/implot")
endif()

set_source_files_properties(${MW05_RECOMP_THIRDPARTY_SOURCES} PROPERTIES SKIP_PRECOMPILE_HEADERS ON)

set(MW05_RECOMP_CXX_SOURCES
    "app.cpp"
    "exports.cpp"
    "main.cpp"
    "misc_impl.cpp"
    "preload_executable.cpp"
    "sdl_listener.cpp"
    "stdafx.cpp"
    "version.cpp"
    "ppc_indirect_hardfix.cpp"
    # Manual override/patch units
    "ppc_runtime_patch_hooks.cpp"
    "ppc_manual_overrides_symbols.cpp"
    "ppc_hook_overrides_manual.cpp"


    ${MW05_RECOMP_KERNEL_CXX_SOURCES}
    ${MW05_RECOMP_LOCALE_CXX_SOURCES}
    ${MW05_RECOMP_OS_CXX_SOURCES}
    ${MW05_RECOMP_CPU_CXX_SOURCES}
    ${MW05_RECOMP_GPU_CXX_SOURCES}
    ${MW05_RECOMP_APU_CXX_SOURCES}
    ${MW05_RECOMP_HID_CXX_SOURCES}
    ${MW05_RECOMP_PATCHES_CXX_SOURCES}
    ${MW05_RECOMP_UI_CXX_SOURCES}
    ${MW05_RECOMP_INSTALL_CXX_SOURCES}
    ${MW05_RECOMP_USER_CXX_SOURCES}
    ${MW05_RECOMP_MOD_CXX_SOURCES}
    ${MW05_RECOMP_THIRDPARTY_SOURCES}
)

# Auto-generate app-side PPC overrides from PPC_FUNC definitions
set(PPC_OVERRIDES_CPP "${CMAKE_BINARY_DIR}/ppc_overrides.gen.cpp")
add_custom_command(
    OUTPUT ${PPC_OVERRIDES_CPP}
    COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
            ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/gen_ppc_overrides.py
                              -D_src=${CMAKE_CURRENT_SOURCE_DIR}
                              -D_out=${PPC_OVERRIDES_CPP}
                              -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/gen_ppc_overrides.py
            ${MW05_RECOMP_CXX_SOURCES}
    COMMENT "Generating PPC override mappings from app sources"
    VERBATIM
)
list(APPEND MW05_RECOMP_CXX_SOURCES ${PPC_OVERRIDES_CPP})

# Optional: generate app hook overrides from CSV mapping (tools/hooks_mw05.csv)
set(PPC_HOOK_OVERRIDES_CPP "${CMAKE_BINARY_DIR}/ppc_hook_overrides.gen.cpp")
add_custom_command(
    OUTPUT ${PPC_HOOK_OVERRIDES_CPP}
    COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
            ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/gen_hook_overrides_from_csv.py
                              -D_csv=${CMAKE_SOURCE_DIR}/tools/hooks_mw05.csv
                              -D_out=${PPC_HOOK_OVERRIDES_CPP}
                              -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_hooks.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/tools/gen_hook_overrides_from_csv.py
            ${CMAKE_SOURCE_DIR}/tools/hooks_mw05.csv
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_hooks.cmake
    COMMENT "Generating app hook overrides from tools/hooks_mw05.csv"
    VERBATIM)
list(APPEND MW05_RECOMP_CXX_SOURCES ${PPC_HOOK_OVERRIDES_CPP})

# Optional: generate stubs for indirect-miss addresses from mw05_debug.log
option(MW05_GEN_INDIRECT_STUBS "Generate stub mappings from mw05_debug.log" OFF)
if (MW05_GEN_INDIRECT_STUBS)
    set(PPC_INDIRECT_CPP "${CMAKE_CURRENT_BINARY_DIR}/ppc_indirect_stubs.gen.cpp")
    add_custom_command(
        OUTPUT ${PPC_INDIRECT_CPP}
        COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
                ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/gen_indirect_stubs.py
                                  -D_src=${CMAKE_CURRENT_SOURCE_DIR}
                                  -D_out=${PPC_INDIRECT_CPP}
                                  -D_log=${CMAKE_BINARY_DIR}/Mw05Recomp/mw05_debug.log
                                  -D_ppc=${CMAKE_SOURCE_DIR}/Mw05RecompLib/ppc
                                  -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_indirect.cmake
        DEPENDS ${CMAKE_SOURCE_DIR}/tools/gen_indirect_stubs.py
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_indirect.cmake
        COMMENT "Generating indirect-call stub mappings from mw05_debug.log"
        VERBATIM)
    list(APPEND MW05_RECOMP_CXX_SOURCES ${PPC_INDIRECT_CPP})
endif()

### Always: extract indirect-miss targets from the runtime log to a stable byproduct
set(PPC_INDIRECT_MISSES_TXT "${CMAKE_CURRENT_BINARY_DIR}/indirect_misses.txt")
add_custom_target(ExtractIndirectMisses
    COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
            ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/extract_indirect_misses.py
                              -D_log=${CMAKE_BINARY_DIR}/Mw05Recomp/mw05_debug.log
                              -D_out=${PPC_INDIRECT_MISSES_TXT}
                              -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_extract.cmake
    BYPRODUCTS ${PPC_INDIRECT_MISSES_TXT}
    COMMENT "Updating indirect-miss list from mw05_debug.log"
    VERBATIM)

option(MW05_GEN_INDIRECT_REDIRECTS "Redirect indirect-miss addresses to nearest function start from IDA HTML" OFF)
if (MW05_GEN_INDIRECT_REDIRECTS)
    set(PPC_INDIRECT_REDIRECTS_CPP "${CMAKE_BINARY_DIR}/ppc_indirect_redirects.gen.cpp")
    add_custom_command(
        OUTPUT ${PPC_INDIRECT_REDIRECTS_CPP}
        COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
                ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/gen_indirect_redirects.py
                                  -D_out=${PPC_INDIRECT_REDIRECTS_CPP}
                                  -D_log=${CMAKE_BINARY_DIR}/Mw05Recomp/mw05_debug.log
                                  -D_misses=${PPC_INDIRECT_MISSES_TXT}
                                  -D_html=${CMAKE_SOURCE_DIR}/NfsMWEurope.xex.html
                                  -D_ppc=${CMAKE_SOURCE_DIR}/Mw05RecompLib/ppc
                                  -D_src=${CMAKE_CURRENT_SOURCE_DIR}
                                  -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_redirects.cmake
        DEPENDS ${CMAKE_SOURCE_DIR}/tools/gen_indirect_redirects.py
                ${CMAKE_SOURCE_DIR}/NfsMWEurope.xex.html
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_redirects.cmake
        COMMENT "Generating indirect-call redirects using IDA HTML"
        VERBATIM)
    list(APPEND MW05_RECOMP_CXX_SOURCES ${PPC_INDIRECT_REDIRECTS_CPP})
endif()

# Generate a hardfix TU directly from extracted misses to ensure exact-address coverage
if (MW05_GEN_INDIRECT_REDIRECTS_HARDFIX)
    set(PPC_INDIRECT_HARDFIX_CPP "${CMAKE_BINARY_DIR}/ppc_indirect_hardfix.gen.cpp")
    add_custom_command(
        OUTPUT ${PPC_INDIRECT_HARDFIX_CPP}
        COMMAND ${CMAKE_COMMAND} -E env PYTHONUTF8=1
                ${CMAKE_COMMAND} -D_py=${CMAKE_SOURCE_DIR}/tools/gen_indirect_hardfix_from_misses.py
                                  -D_misses=${PPC_INDIRECT_MISSES_TXT}
                                  -D_html=${CMAKE_SOURCE_DIR}/NfsMWEurope.xex.html
                                  -D_out=${PPC_INDIRECT_HARDFIX_CPP}
                                  -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_hardfix.cmake
        DEPENDS ${PPC_INDIRECT_MISSES_TXT}
                ${CMAKE_SOURCE_DIR}/tools/gen_indirect_hardfix_from_misses.py
                ${CMAKE_SOURCE_DIR}/NfsMWEurope.xex.html
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/run_python_script_redirects.cmake
        COMMENT "Generating hardfix indirect redirects from misses file"
        VERBATIM)
    list(APPEND MW05_RECOMP_CXX_SOURCES ${PPC_INDIRECT_HARDFIX_CPP})
    
    # Ensure the misses list is updated before compiling the app
    if (TARGET Mw05Recomp)
        add_dependencies(Mw05Recomp ExtractIndirectMisses)
    endif()
endif()

# Optional: auto-generate import stubs for __imp__ functions
option(MW05_GEN_IMPORT_STUBS "Generate import stubs from PPC mapping" OFF)
if (MW05_GEN_IMPORT_STUBS)
    set(PPC_MAP "${CMAKE_SOURCE_DIR}/Mw05RecompLib/ppc/ppc_func_mapping.cpp")
    set(IMPORTS_CPP "${CMAKE_CURRENT_SOURCE_DIR}/kernel/imports.cpp")
    set(GEN_STUBS_CPP "${CMAKE_CURRENT_BINARY_DIR}/imports_autostubs.cpp")
    add_custom_command(
        OUTPUT ${GEN_STUBS_CPP}
        COMMAND ${CMAKE_COMMAND}
                -DPPC_MAP=${PPC_MAP}
                -DIMPORTS_CPP=${IMPORTS_CPP}
                -DOUT_CPP=${GEN_STUBS_CPP}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_import_stubs.cmake
        DEPENDS ${PPC_MAP} ${IMPORTS_CPP} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_import_stubs.cmake
        VERBATIM
    )
    list(APPEND MW05_RECOMP_CXX_SOURCES ${GEN_STUBS_CPP})
endif()

include("version.cmake")

set(VERSION_TXT "${PROJECT_SOURCE_DIR}/res/version.txt")

# Only show Git info and build type if not Release.
set(SHOW_GIT_INFO_AND_BUILD_TYPE 0)
if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Release")
    set(SHOW_GIT_INFO_AND_BUILD_TYPE 1)
endif()

GenerateVersionSources(
    OUTPUT_DIR ${PROJECT_SOURCE_DIR}
    VERSION_TXT ${VERSION_TXT}
    H_TEMPLATE "${PROJECT_SOURCE_DIR}/res/version.h.template"
    CXX_TEMPLATE "${PROJECT_SOURCE_DIR}/res/version.cpp.template"
    BUILD_TYPE ${CMAKE_BUILD_TYPE}
    SHOW_GIT_INFO ${SHOW_GIT_INFO_AND_BUILD_TYPE}
    SHOW_BUILD_TYPE ${SHOW_GIT_INFO_AND_BUILD_TYPE}
)

if (WIN32)
    # Create binary version number for Win32 integer attributes.
    CreateVersionString(
        VERSION_TXT ${VERSION_TXT}
        OUTPUT_CSV 1
        OUTPUT_VAR WIN32_VERSION_BINARY
    )

    # Create string version number for Win32 detailed attributes.
    CreateVersionString(
        VERSION_TXT ${VERSION_TXT}
        BUILD_TYPE ${CMAKE_BUILD_TYPE}
        SHOW_GIT_INFO ${SHOW_GIT_INFO_AND_BUILD_TYPE}
        SHOW_BUILD_TYPE ${SHOW_GIT_INFO_AND_BUILD_TYPE}
        OUTPUT_VAR WIN32_VERSION_STRING
    )

    # Set Win32 icon path.
    set(WIN32_ICON_PATH "${PROJECT_SOURCE_DIR}/../Mw05RecompResources/images/game_icon.ico")

    configure_file("res/win32/res.rc.template" "${CMAKE_BINARY_DIR}/res.rc" @ONLY)
    add_executable(Mw05Recomp ${MW05_RECOMP_CXX_SOURCES} "${CMAKE_BINARY_DIR}/res.rc")

    # Hide console for release configurations.
    if (${CMAKE_BUILD_TYPE} MATCHES "Release")
        target_link_options(Mw05Recomp PRIVATE "/SUBSYSTEM:WINDOWS" "/ENTRY:mainCRTStartup")
    endif()
    elseif (APPLE)
    # Create version number for app bundle.
    CreateVersionString(
        VERSION_TXT ${VERSION_TXT}
        OUTPUT_VAR MACOS_BUNDLE_VERSION
    )

    add_executable(Mw05Recomp MACOSX_BUNDLE
        ${MW05_RECOMP_CXX_SOURCES}
        res/macos/game_icon.icns
    )
    set_source_files_properties(res/macos/game_icon.icns PROPERTIES
        MACOSX_PACKAGE_LOCATION Resources)
    set_target_properties(Mw05Recomp PROPERTIES
        OUTPUT_NAME "Mw05 Recompiled"
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/res/macos/MacOSXBundleInfo.plist.in
        MACOSX_BUNDLE_GUI_IDENTIFIER sh2dow.Mw05Recomp
        MACOSX_BUNDLE_BUNDLE_NAME "Mw05 Recompiled"
        MACOSX_BUNDLE_BUNDLE_VERSION ${MACOS_BUNDLE_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${MACOS_BUNDLE_VERSION}
        MACOSX_BUNDLE_ICON_FILE "game_icon.icns"
    )

    # Linking with MoltenVK directly would prevent using the system Vulkan loader to load with debug layers.
    # Instead, copy the MoltenVK dylib to the app bundle along with an ICD file for the loader to find it.
    # In the event the loader is not installed, the MoltenVK dylib can still be picked up directly in the app bundle.
    set(MVK_BUNDLED_PATH "Resources/vulkan/icd.d")
    set(MVK_DST "${CMAKE_CURRENT_BINARY_DIR}/Mw05 Recompiled.app/Contents/${MVK_BUNDLED_PATH}")
    set_property(TARGET Mw05Recomp APPEND PROPERTY BUILD_RPATH "@executable_path/../${MVK_BUNDLED_PATH}")

    set(MVK_ICD_SRC "${MW05_RECOMP_THIRDPARTY_ROOT}/MoltenVK/MoltenVK/MoltenVK/icd/MoltenVK_icd.json")
    set(MVK_ICD_DST "${MVK_DST}/MoltenVK_icd.json")
    set(MVK_DYLIB_SRC "${CMAKE_BINARY_DIR}/thirdparty/MoltenVK/libMoltenVK.dylib")
    set(MVK_DYLIB_DST "${MVK_DST}/libMoltenVK.dylib")

    add_custom_command(
        OUTPUT ${MVK_DST}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${MVK_DST})
    add_custom_command(
        OUTPUT ${MVK_ICD_DST}
        DEPENDS ${MVK_ICD_SRC} ${MVK_DST}
        COMMAND ${CMAKE_COMMAND} -E copy ${MVK_ICD_SRC} ${MVK_ICD_DST})
    add_custom_command(
        OUTPUT ${MVK_DYLIB_DST}
        DEPENDS ${MVK_DYLIB_SRC} ${MVK_DST}
        COMMAND ${CMAKE_COMMAND} -E copy ${MVK_DYLIB_SRC} ${MVK_DYLIB_DST})
    add_custom_target(CopyMoltenVK DEPENDS ${MVK_ICD_DST} ${MVK_DYLIB_DST})
    add_dependencies(CopyMoltenVK MoltenVK)
    add_dependencies(Mw05Recomp CopyMoltenVK)
else()
    add_executable(Mw05Recomp ${MW05_RECOMP_CXX_SOURCES})
endif()

# Link against the core recompiled library and expose its headers
if (TARGET Mw05Recomp)
    target_link_libraries(Mw05Recomp PRIVATE Mw05RecompLib)
    target_include_directories(Mw05Recomp PRIVATE ${CMAKE_SOURCE_DIR}/Mw05RecompLib)
endif()

# Propagate feature defines
target_compile_definitions(Mw05Recomp PRIVATE
    SDL_ENABLE_OLD_NAMES=1
    MW05_GEN_INDIRECT_REDIRECTS=$<BOOL:${MW05_GEN_INDIRECT_REDIRECTS}>
    MW05_GEN_INDIRECT_REDIRECTS_HARDFIX=$<BOOL:${MW05_GEN_INDIRECT_REDIRECTS_HARDFIX}>
    MW05_ENABLE_UNLEASHED=$<BOOL:${MW05_ENABLE_UNLEASHED}>
    MW05_ENABLE_IMPLOT=$<BOOL:${MW05_ENABLE_IMPLOT}>)

if (MW05_RECOMP_FLATPAK)
    target_compile_definitions(Mw05Recomp PRIVATE
        "MW05_RECOMP_FLATPAK"
        "GAME_INSTALL_DIRECTORY=\"/var/data\""
    )
endif()

find_package(CURL REQUIRED)

if (MW05_RECOMP_D3D12)
    find_package(directx-headers CONFIG REQUIRED)
    find_package(directx12-agility CONFIG REQUIRED)
    target_compile_definitions(Mw05Recomp PRIVATE MW05_RECOMP_D3D12)

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/D3D12)
    add_custom_command(TARGET Mw05Recomp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:Microsoft::DirectX12-Core,IMPORTED_LOCATION_RELEASE> $<TARGET_FILE_DIR:Mw05Recomp>/D3D12
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:Microsoft::DirectX12-Layers,IMPORTED_LOCATION_DEBUG> $<TARGET_FILE_DIR:Mw05Recomp>/D3D12
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:Microsoft::DirectXShaderCompiler,IMPORTED_LOCATION> $<TARGET_FILE_DIR:Mw05Recomp>
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PROPERTY:Microsoft::DXIL,IMPORTED_LOCATION> $<TARGET_FILE_DIR:Mw05Recomp>
        COMMAND_EXPAND_LISTS
    )

    target_link_libraries(Mw05Recomp PRIVATE
        Microsoft::DirectXShaderCompiler
        Microsoft::DXIL
        dxgi
    )
endif()

if (WIN32)
    target_link_libraries(Mw05Recomp PRIVATE
        comctl32
        dwmapi
        ntdll
        Shcore
        Synchronization
        winmm
        windowsapp
    )
endif()
    # Generate a .map file for quick address-to-symbol lookup during crash triage
    target_link_options(Mw05Recomp PRIVATE "/MAP")


target_link_libraries(Mw05Recomp PRIVATE
    fmt::fmt
    libzstd_static
    msdf-atlas-gen::msdf-atlas-gen
    nfd::nfd
    o1heap
    XenonUtils
    SDL3::SDL3-static            # <- was SDL2::SDL2-static
    SDL3_mixer::SDL3_mixer       # <- was SDL2_mixer
    tomlplusplus::tomlplusplus
    Mw05RecompLib
    xxHash::xxhash
    CURL::libcurl
    plume
)

## SWA is removed; no SWA-specific compile definitions

if (MW05_ENABLE_INSTALLER)
    target_compile_definitions(Mw05Recomp PRIVATE MW05_ENABLE_INSTALLER)
endif()

if (MW05_ENABLE_UI)
    target_compile_definitions(Mw05Recomp PRIVATE MW05_ENABLE_UI)
endif()

target_include_directories(Mw05Recomp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/api"
    ${MW05_RECOMP_THIRDPARTY_INCLUDES}
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    find_package(X11 REQUIRED)
    target_include_directories(Mw05Recomp PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(Mw05Recomp PRIVATE ${X11_LIBRARIES})
endif()

option(MW05_SKIP_APP_PCH "Disable PCH for Mw05Recomp target" OFF)
if (NOT MW05_SKIP_APP_PCH)
    target_precompile_headers(Mw05Recomp PUBLIC ${MW05_RECOMP_PRECOMPILED_HEADERS})
endif()

function(compile_shader FILE_PATH TARGET_NAME)
    set(FILE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/gpu/shader/${FILE_PATH}.hlsl)
    cmake_path(GET FILE_PATH STEM VARIABLE_NAME)
    if (MW05_RECOMP_D3D12)
        add_custom_command(
            OUTPUT ${FILE_PATH}.dxil.h
            COMMAND ${DIRECTX_DXC_TOOL} -T ${TARGET_NAME} -HV 2021 -all-resources-bound -Wno-ignored-attributes -Fh ${FILE_PATH}.dxil.h ${FILE_PATH} -Vn g_${VARIABLE_NAME}_dxil
            DEPENDS ${FILE_PATH}
        )
        target_sources(Mw05Recomp PRIVATE ${FILE_PATH}.dxil.h)
    endif()
    add_custom_command(
        OUTPUT ${FILE_PATH}.spirv.h
        COMMAND ${DIRECTX_DXC_TOOL} -T ${TARGET_NAME} -HV 2021 -all-resources-bound -spirv -fvk-use-dx-layout ${ARGN} -Fh ${FILE_PATH}.spirv.h ${FILE_PATH} -Vn g_${VARIABLE_NAME}_spirv
        DEPENDS ${FILE_PATH}
    )
    target_sources(Mw05Recomp PRIVATE ${FILE_PATH}.spirv.h)
endfunction()

function(compile_vertex_shader FILE_PATH)
    compile_shader(${FILE_PATH} vs_6_0 -fvk-invert-y -DMW05_RECOMP)
endfunction()

function(compile_pixel_shader FILE_PATH)
    compile_shader(${FILE_PATH} ps_6_0 -DMW05_RECOMP)
endfunction()

compile_pixel_shader(blend_color_alpha_ps)
compile_vertex_shader(copy_vs)
compile_pixel_shader(copy_color_ps)
compile_pixel_shader(copy_depth_ps)
compile_pixel_shader(csd_filter_ps)
compile_vertex_shader(csd_no_tex_vs)
compile_vertex_shader(csd_vs)
compile_pixel_shader(enhanced_motion_blur_ps)
compile_pixel_shader(gaussian_blur_3x3)
compile_pixel_shader(gaussian_blur_5x5)
compile_pixel_shader(gaussian_blur_7x7)
compile_pixel_shader(gaussian_blur_9x9)
compile_pixel_shader(gamma_correction_ps)
compile_pixel_shader(imgui_ps)
compile_vertex_shader(imgui_vs)
compile_pixel_shader(movie_ps)
compile_vertex_shader(movie_vs)
compile_pixel_shader(resolve_msaa_color_2x)
compile_pixel_shader(resolve_msaa_color_4x)
compile_pixel_shader(resolve_msaa_color_8x)
compile_pixel_shader(resolve_msaa_depth_2x)
compile_pixel_shader(resolve_msaa_depth_4x)
compile_pixel_shader(resolve_msaa_depth_8x)

set(RESOURCES_SOURCE_PATH "${PROJECT_SOURCE_DIR}/../Mw05RecompResources")
set(RESOURCES_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/res")

## Miscellaneous ##
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/bc_diff/button_bc_diff.bin" DEST_FILE "${RESOURCES_OUTPUT_PATH}/bc_diff/button_bc_diff.bin" ARRAY_NAME "g_button_bc_diff" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/font/im_font_atlas.bin" DEST_FILE "${RESOURCES_OUTPUT_PATH}/font/im_font_atlas.bin" ARRAY_NAME "g_im_font_atlas" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/font/im_font_atlas.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/font/im_font_atlas.dds" ARRAY_NAME "g_im_font_atlas_texture" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/achievements_menu/trophy.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/achievements_menu/trophy.dds" ARRAY_NAME "g_trophy" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/controller.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/controller.dds" ARRAY_NAME "g_controller" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/general_window.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/general_window.dds" ARRAY_NAME "g_general_window" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/mw05recomp.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/mw05recomp.dds" ARRAY_NAME "g_hedgedev" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/kbm.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/kbm.dds" ARRAY_NAME "g_kbm" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/select.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/select.dds" ARRAY_NAME "g_select" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/common/light.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/common/light.dds" ARRAY_NAME "g_light" COMPRESSION_TYPE "zstd")

## Installer ##
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/arrow_circle.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/arrow_circle.dds" ARRAY_NAME "g_arrow_circle" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_001.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_001.dds" ARRAY_NAME "g_install_001" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_002.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_002.dds" ARRAY_NAME "g_install_002" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_003.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_003.dds" ARRAY_NAME "g_install_003" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_004.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_004.dds" ARRAY_NAME "g_install_004" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_005.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_005.dds" ARRAY_NAME "g_install_005" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_006.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_006.dds" ARRAY_NAME "g_install_006" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_007.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_007.dds" ARRAY_NAME "g_install_007" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/install_008.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/install_008.dds" ARRAY_NAME "g_install_008" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/miles_electric_icon.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/miles_electric_icon.dds" ARRAY_NAME "g_miles_electric_icon" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/installer/pulse_install.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/installer/pulse_install.dds" ARRAY_NAME "g_pulse_install" COMPRESSION_TYPE "zstd")

## Options Menu ##
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/achievement_notifications.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/achievement_notifications.dds" ARRAY_NAME "g_achievement_notifications" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/allow_background_input_ps.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/allow_background_input_ps.dds" ARRAY_NAME "g_allow_background_input_ps" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/allow_background_input_xb.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/allow_background_input_xb.dds" ARRAY_NAME "g_allow_background_input_xb" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/antialiasing_none.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/antialiasing_none.dds" ARRAY_NAME "g_antialiasing_none" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/antialiasing_2x.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/antialiasing_2x.dds" ARRAY_NAME "g_antialiasing_2x" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/antialiasing_4x.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/antialiasing_4x.dds" ARRAY_NAME "g_antialiasing_4x" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/antialiasing_8x.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/antialiasing_8x.dds" ARRAY_NAME "g_antialiasing_8x" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/aspect_ratio.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/aspect_ratio.dds" ARRAY_NAME "g_aspect_ratio" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/battle_theme.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/battle_theme.dds" ARRAY_NAME "g_battle_theme" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/brightness.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/brightness.dds" ARRAY_NAME "g_brightness" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/channel_stereo.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/channel_stereo.dds" ARRAY_NAME "g_channel_stereo" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/channel_surround.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/channel_surround.dds" ARRAY_NAME "g_channel_surround" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/control_tutorial_ps.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/control_tutorial_ps.dds" ARRAY_NAME "g_control_tutorial_ps" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/control_tutorial_xb.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/control_tutorial_xb.dds" ARRAY_NAME "g_control_tutorial_xb" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/controller_icons.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/controller_icons.dds" ARRAY_NAME "g_controller_icons" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/default.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/default.dds" ARRAY_NAME "g_default" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/effects_volume.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/effects_volume.dds" ARRAY_NAME "g_effects_volume" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/fps.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/fps.dds" ARRAY_NAME "g_fps" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/fullscreen.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/fullscreen.dds" ARRAY_NAME "g_fullscreen" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/gi_texture_filtering_bilinear.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/gi_texture_filtering_bilinear.dds" ARRAY_NAME "g_gi_texture_filtering_bilinear" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/gi_texture_filtering_bicubic.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/gi_texture_filtering_bicubic.dds" ARRAY_NAME "g_gi_texture_filtering_bicubic" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/hints.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/hints.dds" ARRAY_NAME "g_hints" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/horizontal_camera.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/horizontal_camera.dds" ARRAY_NAME "g_horizontal_camera" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/language.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/language.dds" ARRAY_NAME "g_language" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/master_volume.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/master_volume.dds" ARRAY_NAME "g_master_volume" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/monitor.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/monitor.dds" ARRAY_NAME "g_monitor" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/motion_blur_off.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/motion_blur_off.dds" ARRAY_NAME "g_motion_blur_off" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/motion_blur_original.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/motion_blur_original.dds" ARRAY_NAME "g_motion_blur_original" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/motion_blur_enhanced.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/motion_blur_enhanced.dds" ARRAY_NAME "g_motion_blur_enhanced" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/movie_scale_fit.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/movie_scale_fit.dds" ARRAY_NAME "g_movie_scale_fit" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/movie_scale_fill.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/movie_scale_fill.dds" ARRAY_NAME "g_movie_scale_fill" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/music_attenuation.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/music_attenuation.dds" ARRAY_NAME "g_music_attenuation" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/music_volume.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/music_volume.dds" ARRAY_NAME "g_music_volume" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/shadow_resolution_x512.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/shadow_resolution_x512.dds" ARRAY_NAME "g_shadow_resolution_x512" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/shadow_resolution_x1024.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/shadow_resolution_x1024.dds" ARRAY_NAME "g_shadow_resolution_x1024" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/shadow_resolution_x2048.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/shadow_resolution_x2048.dds" ARRAY_NAME "g_shadow_resolution_x2048" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/shadow_resolution_x4096.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/shadow_resolution_x4096.dds" ARRAY_NAME "g_shadow_resolution_x4096" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/shadow_resolution_x8192.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/shadow_resolution_x8192.dds" ARRAY_NAME "g_shadow_resolution_x8192" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/time_transition_ps.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/time_transition_ps.dds" ARRAY_NAME "g_time_of_day_transition_playstation" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/time_transition_xb.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/time_transition_xb.dds" ARRAY_NAME "g_time_of_day_transition_xbox" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/transparency_antialiasing_false.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/transparency_antialiasing_false.dds" ARRAY_NAME "g_transparency_antialiasing_false" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/transparency_antialiasing_true.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/transparency_antialiasing_true.dds" ARRAY_NAME "g_transparency_antialiasing_true" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/ui_alignment_centre.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/ui_alignment_centre.dds" ARRAY_NAME "g_ui_alignment_centre" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/ui_alignment_edge.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/ui_alignment_edge.dds" ARRAY_NAME "g_ui_alignment_edge" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/vertical_camera.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/vertical_camera.dds" ARRAY_NAME "g_vertical_camera" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/voice_language.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/voice_language.dds" ARRAY_NAME "g_voice_language" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/vibration_ps.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/vibration_ps.dds" ARRAY_NAME "g_vibration_ps" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/vibration_xb.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/vibration_xb.dds" ARRAY_NAME "g_vibration_xb" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/vsync_on.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/vsync_on.dds" ARRAY_NAME "g_vsync_on" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/vsync_off.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/vsync_off.dds" ARRAY_NAME "g_vsync_off" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/window_size.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/window_size.dds" ARRAY_NAME "g_window_size" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/thumbnails/xbox_color_correction.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/thumbnails/xbox_color_correction.dds" ARRAY_NAME "g_xbox_color_correction" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/miles_electric.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/miles_electric.dds" ARRAY_NAME "g_miles_electric" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/options_static.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/options_static.dds" ARRAY_NAME "g_options_static" COMPRESSION_TYPE "zstd")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/options_menu/options_static_flash.dds" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/options_menu/options_static_flash.dds" ARRAY_NAME "g_options_static_flash" COMPRESSION_TYPE "zstd")

## Game Icon ##
## SWA removed
option(MW05_ENABLE_INSTALLER "Enable installer UI and content flow" ON)
option(MW05_ENABLE_UI "Enable app UI (menus/overlays)" ON)

BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/game_icon.bmp" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/game_icon.bmp" ARRAY_NAME "g_game_icon")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/images/game_icon_night.bmp" DEST_FILE "${RESOURCES_OUTPUT_PATH}/images/game_icon_night.bmp" ARRAY_NAME "g_game_icon_night")

## Audio ##
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/music/installer.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/music/installer.ogg" ARRAY_NAME "g_installer_music")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_worldmap_cursor.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_worldmap_cursor.ogg" ARRAY_NAME "g_sys_worldmap_cursor")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_worldmap_finaldecide.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_worldmap_finaldecide.ogg" ARRAY_NAME "g_sys_worldmap_finaldecide")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_actstg_pausecansel.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_actstg_pausecansel.ogg" ARRAY_NAME "g_sys_actstg_pausecansel")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_actstg_pausecursor.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_actstg_pausecursor.ogg" ARRAY_NAME "g_sys_actstg_pausecursor")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_actstg_pausedecide.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_actstg_pausedecide.ogg" ARRAY_NAME "g_sys_actstg_pausedecide")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_actstg_pausewinclose.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_actstg_pausewinclose.ogg" ARRAY_NAME "g_sys_actstg_pausewinclose")
BIN2C(TARGET_OBJ Mw05Recomp SOURCE_FILE "${RESOURCES_SOURCE_PATH}/sounds/sys_actstg_pausewinopen.ogg" DEST_FILE "${RESOURCES_OUTPUT_PATH}/sounds/sys_actstg_pausewinopen.ogg" ARRAY_NAME "g_sys_actstg_pausewinopen")
