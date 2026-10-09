file(GLOB_RECURSE PQ_FORMAT_SOURCES CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/include/*.hpp
  ${PROJECT_SOURCE_DIR}/src/*.hpp ${PROJECT_SOURCE_DIR}/src/*.cpp
  ${PROJECT_SOURCE_DIR}/apps/*.hpp ${PROJECT_SOURCE_DIR}/apps/*.cpp
  ${PROJECT_SOURCE_DIR}/bench/*.hpp ${PROJECT_SOURCE_DIR}/bench/*.cpp
  ${PROJECT_SOURCE_DIR}/analysis/*.hpp ${PROJECT_SOURCE_DIR}/analysis/*.cpp
  ${PROJECT_SOURCE_DIR}/tests/*.hpp ${PROJECT_SOURCE_DIR}/tests/*.cpp)

find_program(CLANG_FORMAT_EXE clang-format)
if(CLANG_FORMAT_EXE)
  add_custom_target(format COMMAND ${CLANG_FORMAT_EXE} -i ${PQ_FORMAT_SOURCES})
  add_custom_target(format-check
    COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${PQ_FORMAT_SOURCES})
endif()

find_program(CLANG_TIDY_EXE clang-tidy)
if(CLANG_TIDY_EXE)
  file(GLOB_RECURSE PQ_TIDY_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)
  add_custom_target(tidy
    COMMAND ${CLANG_TIDY_EXE} -p ${CMAKE_BINARY_DIR} ${PQ_TIDY_SOURCES})
endif()
