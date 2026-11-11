add_subdirectory(${PROJECT_SOURCE_DIR}/analysis/avalanche ${CMAKE_CURRENT_BINARY_DIR}/avalanche)
add_subdirectory(${PROJECT_SOURCE_DIR}/analysis/sbox ${CMAKE_CURRENT_BINARY_DIR}/sbox)
target_link_libraries(pq_unit_tests PRIVATE pq_analysis)
target_sources(pq_unit_tests PRIVATE avalanche_test.cpp sbox_test.cpp real_analysis_test.cpp)
