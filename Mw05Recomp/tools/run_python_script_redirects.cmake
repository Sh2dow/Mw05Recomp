cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED _py)
  message(FATAL_ERROR "run_python_script_redirects.cmake requires -D_py=<script.py>")
endif()
if(NOT DEFINED _out)
  message(FATAL_ERROR "run_python_script_redirects.cmake requires -D_out=<out.cpp>")
endif()
if(NOT DEFINED _log)
  set(_log "mw05_debug.log")
endif()
if(NOT DEFINED _html)
  set(_html "NfsMWEurope.xex.html")
endif()
if(NOT DEFINED _ppc)
  set(_ppc "Mw05RecompLib/ppc")
endif()
if(NOT DEFINED _src)
  set(_src "Mw05Recomp")
endif()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  set(_python ${Python3_EXECUTABLE})
else()
  set(_python python)
endif()

execute_process(
  COMMAND ${_python} ${_py} --log ${_log} --html ${_html} --ppc-root ${_ppc} --app-root ${_src} --out-cpp ${_out}
  RESULT_VARIABLE _res
)
if(NOT _res EQUAL 0)
  message(FATAL_ERROR "Failed to run ${_py} (rc=${_res})")
endif()

