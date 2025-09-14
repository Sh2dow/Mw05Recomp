cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED _py)
  message(FATAL_ERROR "run_python_script_hardfix.cmake requires -D_py=<script.py>")
endif()
if(NOT DEFINED _misses)
  message(FATAL_ERROR "run_python_script_hardfix.cmake requires -D_misses=<indirect_misses.txt>")
endif()
if(NOT DEFINED _html)
  set(_html "NfsMWEurope.xex.html")
endif()
if(NOT DEFINED _out)
  message(FATAL_ERROR "run_python_script_hardfix.cmake requires -D_out=<out.cpp>")
endif()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  set(_python ${Python3_EXECUTABLE})
else()
  set(_python python)
endif()

execute_process(
  COMMAND ${_python} ${_py} --misses ${_misses} --html ${_html} --out-cpp ${_out}
  RESULT_VARIABLE _res
)
if(NOT _res EQUAL 0)
  message(FATAL_ERROR "Failed to run ${_py} (rc=${_res})")
endif()

