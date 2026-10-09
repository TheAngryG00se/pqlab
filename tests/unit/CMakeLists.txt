add_executable(pq_unit_tests)
target_include_directories(pq_unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(pq_unit_tests PRIVATE pqlab pq_warnings GTest::gtest_main)
target_compile_definitions(pq_unit_tests PRIVATE PQ_KAT_DIR="${PROJECT_SOURCE_DIR}/tests/kat")

add_subdirectory(core)
add_subdirectory(hash)
add_subdirectory(mlkem)

gtest_discover_tests(pq_unit_tests DISCOVERY_TIMEOUT 60)
