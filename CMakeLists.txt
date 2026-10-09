# Zone: participant 4. Minimal skeleton written by participant 1 so that the
# core and hash layers can be built and tested; to be extended by participant 4.
cmake_minimum_required(VERSION 3.22)

project(pqlab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PQ_BUILD_TESTS "Unit tests and KAT" ON)
option(PQ_BUILD_BENCH "pqbench" ON)
option(PQ_BUILD_FUZZ "libFuzzer targets (Clang only)" OFF)
option(PQ_WITH_REFERENCE "OpenSSL and liboqs for tests/diff and bench" OFF)
set(PQ_SANITIZE "" CACHE STRING "Sanitizers, e.g. address,undefined")

include(cmake/warnings.cmake)
include(cmake/sanitizers.cmake)
include(cmake/tools.cmake)

add_library(pqlab STATIC)
target_include_directories(pqlab
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pqlab PRIVATE pq_warnings)

add_subdirectory(src)

if(PQ_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
