add_library(pq_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(pq_warnings INTERFACE -Wall -Wextra -Wpedantic -Werror)
endif()
