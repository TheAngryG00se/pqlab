add_executable(pqtool main.cpp file_io.cpp)
target_include_directories(pqtool PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(pqtool PRIVATE pqlab pq_warnings)
