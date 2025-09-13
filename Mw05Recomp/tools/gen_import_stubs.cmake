cmake_minimum_required(VERSION 3.20)

# Inputs:
#  - PPC_MAP: path to Mw05RecompLib/ppc/ppc_func_mapping.cpp
#  - IMPORTS_CPP: path to Mw05Recomp/kernel/imports.cpp
#  - OUT_CPP: output path for generated stubs .cpp

if(NOT PPC_MAP OR NOT IMPORTS_CPP OR NOT OUT_CPP)
  message(FATAL_ERROR "gen_import_stubs.cmake requires PPC_MAP, IMPORTS_CPP, OUT_CPP")
endif()

file(READ "${PPC_MAP}" PPC_MAP_TEXT)
file(READ "${IMPORTS_CPP}" IMPORTS_TEXT)

# Collect all __imp__ symbols referenced by mapping
string(REGEX MATCHALL "__imp__[_A-Za-z0-9]+" ALL_IMPS "${PPC_MAP_TEXT}")
list(REMOVE_DUPLICATES ALL_IMPS)

# Collect already provided imports anywhere in app sources (hooks or stubs)
file(GLOB_RECURSE APP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
set(PROVIDED)
foreach(src ${APP_SOURCES})
  file(READ "${src}" SRC_TEXT)
  string(REGEX MATCHALL "__imp__[_A-Za-z0-9]+" TOKENS "${SRC_TEXT}")
  if(TOKENS)
    list(APPEND PROVIDED ${TOKENS})
  endif()
endforeach()
list(REMOVE_DUPLICATES PROVIDED)

# Compute missing = ALL_IMPS - PROVIDED
set(MISSING)
foreach(sym ${ALL_IMPS})
  list(FIND PROVIDED "${sym}" idx)
  if(idx EQUAL -1)
    list(APPEND MISSING "${sym}")
  endif()
endforeach()
list(REMOVE_DUPLICATES MISSING)

# Write output file
file(WRITE "${OUT_CPP}" "#include <stdafx.h>\n#include <kernel/function.h>\n\n// Auto-generated import stubs (missing in imports.cpp)\n")
foreach(sym ${MISSING})
  file(APPEND "${OUT_CPP}" "GUEST_FUNCTION_STUB(${sym});\n")
endforeach()

message(STATUS "Generated ${OUT_CPP} with ${MISSING}" )
