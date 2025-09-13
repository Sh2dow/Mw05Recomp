cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED _py)
  message(FATAL_ERROR "run_python_script.cmake requires -D_py=<script.py>")
endif()

if(NOT DEFINED _out)
  set(_out "")
endif()

if(NOT DEFINED _src)
  set(_src "")
endif()

# Prefer Python3 from CMake if found
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  set(_python ${Python3_EXECUTABLE})
else()
  # Fallback to 'python'
  set(_python python)
endif()

execute_process(
  COMMAND ${_python} ${_py} --src-root ${_src} --out-cpp ${_out}
  RESULT_VARIABLE _res
)
if(NOT _res EQUAL 0)
  message(FATAL_ERROR "Failed to run ${_py} (rc=${_res})")
endif()

