add_executable(gk-cli main.cpp)
target_link_libraries(gk-cli PRIVATE gk_scan)
gk_apply_options(gk-cli)
