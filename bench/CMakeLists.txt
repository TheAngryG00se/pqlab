find_package(Git QUIET)
set(PQ_BENCH_COMMIT "unknown")
if(GIT_FOUND)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE PQ_BENCH_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE PQ_BENCH_DIRTY)
  if(NOT PQ_BENCH_DIRTY STREQUAL "")
    string(APPEND PQ_BENCH_COMMIT "-dirty")
  endif()
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" PQ_BENCH_CONFIG)
set(PQ_BENCH_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${PQ_BENCH_CONFIG}} -std=c++20 -Wall -Wextra -Wpedantic -Werror")
configure_file(build_info.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/bench_build_info.hpp @ONLY)

add_library(pq_bench STATIC statistics.cpp csv.cpp metadata.cpp suites.cpp)
target_include_directories(pq_bench PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(pq_bench PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pq_bench PUBLIC pqlab PRIVATE pq_warnings)
