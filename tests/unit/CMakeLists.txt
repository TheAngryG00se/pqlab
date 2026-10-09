add_executable(pq_unit_tests)
target_include_directories(pq_unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(pq_unit_tests PRIVATE pq_headers pq_warnings GTest::gtest_main)
target_compile_definitions(pq_unit_tests PRIVATE PQ_KAT_DIR="${PROJECT_SOURCE_DIR}/tests/kat")

add_subdirectory(core)

gtest_discover_tests(pq_unit_tests DISCOVERY_TIMEOUT 60)
