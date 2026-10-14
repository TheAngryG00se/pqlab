# Deliberately local: production build/global Registry belong to participant 4.
target_sources(pq_unit_tests PRIVATE
  ${PROJECT_SOURCE_DIR}/src/cipher/aes.cpp
  aes_test.cpp
  register_test.cpp)
