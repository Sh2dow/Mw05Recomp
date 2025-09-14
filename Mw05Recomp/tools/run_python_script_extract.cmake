cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED _py)
  message(FATAL_ERROR "run_python_script_extract.cmake requires -D_py=<script.py>")
endif()
if(NOT DEFINED _log)
  set(_log "mw05_debug.log")
endif()
if(NOT DEFINED _out)
  message(FATAL_ERROR "run_python_script_extract.cmake requires -D_out=<out.txt>")
endif()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  set(_python ${Python3_EXECUTABLE})
else()
  set(_python python)
endif()

execute_process(
  COMMAND ${_python} ${_py} --log ${_log} --out ${_out} --merge
  RESULT_VARIABLE _res)
if(NOT _res EQUAL 0)
  message(FATAL_ERROR "Failed to run ${_py} (rc=${_res})")
endif()
