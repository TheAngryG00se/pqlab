target_sources(pq_unit_tests PRIVATE
  ${PROJECT_SOURCE_DIR}/src/mode/padding.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/ecb.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/cbc.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/ctr.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/ghash.cpp
  ${PROJECT_SOURCE_DIR}/src/mode/gcm.cpp
  padding_test.cpp
  modes_test.cpp
  ghash_test.cpp
  gcm_test.cpp
  hybrid_real_test.cpp)
