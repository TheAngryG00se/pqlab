add_library(pq_bench STATIC statistics.cpp csv.cpp)
target_include_directories(pq_bench PUBLIC ${PROJECT_SOURCE_DIR})
target_link_libraries(pq_bench PUBLIC pqlab PRIVATE pq_warnings)
