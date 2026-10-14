target_sources(pq_unit_tests PRIVATE
  ${PROJECT_SOURCE_DIR}/src/mode/padding.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/ecb.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/cbc.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/ctr.cpp
  padding_test.cpp
  modes_test.cpp)
