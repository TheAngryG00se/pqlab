cmake_minimum_required(VERSION 3.24)
project(hqc_avalanche_reference LANGUAGES C CXX)

option(PQ_WITH_REFERENCE "Enable the external HQC verification experiment" OFF)
if(NOT PQ_WITH_REFERENCE)
  message(FATAL_ERROR "Set PQ_WITH_REFERENCE=ON to build the HQC reference experiment")
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Point only at the SHA-256-verified v5.1.0 snapshot extracted by the runner.
set(common "${HQC_SOURCE}/src/common")
set(ref "${HQC_SOURCE}/src/ref")
set(fips "${HQC_SOURCE}/lib/fips202")
add_library(hqc_fips202 STATIC "${fips}/fips202.c")
target_include_directories(hqc_fips202 PUBLIC "${fips}")
add_library(hqc_kat_rng STATIC "${HQC_SOURCE}/lib/nist-rng/rng.c")
target_compile_definitions(hqc_kat_rng PRIVATE randombytes=hqc_kat_randombytes)
target_link_libraries(hqc_kat_rng PRIVATE OpenSSL::Crypto)

file(GLOB common_c "${common}/*.c")
file(GLOB ref_c "${ref}/*.c")
foreach(level 1 3 5)
  add_executable(avalanche_${level} adapter.cpp ${common_c} ${ref_c})
  target_compile_definitions(avalanche_${level} PRIVATE HQC_ARCH_REF=1)
  target_include_directories(avalanche_${level} PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../include" "${common}" "${common}/hqc-${level}"
    "${ref}" "${ref}/hqc-${level}")
  target_link_libraries(avalanche_${level} PRIVATE hqc_fips202 hqc_kat_rng)
endforeach()
