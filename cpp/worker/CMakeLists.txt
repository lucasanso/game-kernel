add_executable(gk-scanworker main.cpp)
target_link_libraries(gk-scanworker PRIVATE gk_core)
gk_apply_options(gk-scanworker)
