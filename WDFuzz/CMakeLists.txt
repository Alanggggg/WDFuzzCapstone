cmake_minimum_required(VERSION 3.4)

project(WDFuzz)

include(FindPkgConfig)
pkg_check_modules (LIBVMI REQUIRED libvmi)
pkg_check_modules (CAPSTONE REQUIRED capstone)

add_compile_options(-Wall -Wextra -O2)

include_directories(${CAPSTONE_INCLUDE_DIRS})
add_executable(WDFuzz src/main.c src/signals.c src/vmi.c src/afl.c src/tracer.c src/fuzz.c src/breakpoint.c)
target_link_libraries(WDFuzz ${LIBVMI_LIBRARIES} ${CAPSTONE_LIBRARIES})