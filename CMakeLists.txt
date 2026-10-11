# Zone: participant 4. Minimal skeleton written by participant 1 so that the
# core and hash layers can be built and tested; to be extended by participant 4.
cmake_minimum_required(VERSION 3.24)

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

include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d)
FetchContent_MakeAvailable(nlohmann_json)

add_library(pqlab STATIC)
target_include_directories(pqlab
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pqlab PRIVATE pq_warnings nlohmann_json::nlohmann_json)

add_subdirectory(src)

if(PQ_BUILD_BENCH)
  add_subdirectory(bench)
  add_subdirectory(apps/pqbench)
endif()

if(PQ_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
