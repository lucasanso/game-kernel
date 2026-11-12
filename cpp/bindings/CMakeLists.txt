find_package(Python 3.11 REQUIRED COMPONENTS Interpreter Development.Module)
if(NOT pybind11_DIR)
  execute_process(COMMAND "${Python_EXECUTABLE}" -c "import pybind11; print(pybind11.get_cmake_dir())"
                  OUTPUT_VARIABLE _gk_pybind11_dir OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(_gk_pybind11_dir)
    set(pybind11_DIR "${_gk_pybind11_dir}")
  endif()
endif()
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(gk_native gk_native.cpp)
target_link_libraries(gk_native PRIVATE gk_core)
gk_apply_options(gk_native)
