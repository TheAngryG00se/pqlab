#pragma once

#include <cstdint>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

namespace pq::bench {

// The memory barrier makes results observable even with link-time optimisation.
template <typename T>
inline void do_not_optimize(const T& value) {
#if defined(__GNUC__) || defined(__clang__)
  asm volatile("" : : "g"(&value) : "memory");
#else
  const volatile T* observed = &value;
  (void)observed;
#endif
}

inline constexpr bool kHasCycles =
#if defined(__x86_64__) || defined(__i386__)
    true;
#else
    false;
#endif

// These are TSC ticks, not the changing core frequency's clock cycles.
inline uint64_t read_cycles() {
#if defined(__x86_64__) || defined(__i386__)
  _mm_lfence();
  const uint64_t ticks = __rdtsc();
  _mm_lfence();
  return ticks;
#else
  return 0;
#endif
}

}  // namespace pq::bench
