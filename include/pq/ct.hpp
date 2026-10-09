#pragma once

// Constant-time helpers. Every function here runs in time that depends only on
// the lengths of its arguments (lengths are treated as public), never on the
// contents.

#include <cstddef>
#include <cstdint>
#include <span>

#include "pq/error.hpp"
#include "pq/secure_bytes.hpp"

namespace pq {

// Hides a value from the optimizer so it cannot turn mask arithmetic back into
// a branch.
template <typename T>
[[nodiscard]] inline T ct_value_barrier(T x) noexcept {
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(x) : :);
#endif
  return x;
}

// 0xFF if x == 0, 0x00 otherwise.
[[nodiscard]] inline uint8_t ct_is_zero_mask(uint32_t x) noexcept {
  x = ct_value_barrier(x);
  // (x | -x) has its top bit set iff x != 0.
  const uint32_t nonzero = (x | (0U - x)) >> 31;
  return static_cast<uint8_t>(nonzero - 1U);
}

// 0xFF if a and b are equal, 0x00 otherwise. Buffers of different length are
// unequal (length is public).
[[nodiscard]] inline uint8_t ct_equal_mask(ByteView a, ByteView b) noexcept {
  if (a.size() != b.size()) {
    return 0;
  }
  uint32_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint32_t>(a[i] ^ b[i]);
  }
  return ct_is_zero_mask(diff);
}

// The result is a public decision (e.g. a MAC check), so returning bool is fine.
[[nodiscard]] inline bool ct_equal(ByteView a, ByteView b) noexcept {
  return ct_equal_mask(a, b) != 0;
}

// out = (mask == 0xFF) ? a : b. mask must be 0x00 or 0xFF.
// All three buffers must have the same length.
inline void ct_select(MutByteView out, ByteView a, ByteView b, uint8_t mask) {
  if (out.size() != a.size() || out.size() != b.size()) {
    throw Error("ct_select: length mismatch");
  }
  const uint8_t m = ct_value_barrier(mask);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(b[i] ^ (m & (a[i] ^ b[i])));
  }
}

}  // namespace pq
