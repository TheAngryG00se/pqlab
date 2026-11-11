# Participant 4 can add_subdirectory(cipher) from src/CMakeLists.txt.
# Participant 3's tests compile these sources directly until that integration.
target_sources(pqlab PRIVATE aes.cpp kuznyechik.cpp)
