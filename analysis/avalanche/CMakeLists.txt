add_library(pq_analysis STATIC avalanche.cpp experiments.cpp)
target_include_directories(pq_analysis PUBLIC ${PROJECT_SOURCE_DIR})
target_link_libraries(pq_analysis PUBLIC pqlab PRIVATE pq_warnings)
