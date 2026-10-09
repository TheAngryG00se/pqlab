#pragma once

// Constant-time arithmetic modulo q = 3329 on unsigned integers.
// No division or % by q anywhere (KyberSlash); no shifts of signed values.
// Each helper documents its input range; the ranges are checked exhaustively
// in tests/unit/mlkem/reduce_test.cpp.

#include <cstdint>

#include "kem/mlkem/params.hpp"

namespace pq::mlkem::detail {

// x < 2q -> x mod q.
[[nodiscard]] constexpr uint16_t csubq(uint32_t x) noexcept {
  const uint32_t d = x - kQ;             // wraps if x < q
  const uint32_t mask = 0U - (d >> 31);  // all ones iff x < q
  return static_cast<uint16_t>(d + (mask & kQ));
}

// Barrett reduction: a < 2^26 -> a mod q.
// t = floor(a * floor(2^38 / q) / 2^38) undershoots floor(a / q) by at most 1.
inline constexpr uint64_t kBarrettMul = (uint64_t{1} << 38) / kQ;

[[nodiscard]] constexpr uint16_t barrett_reduce(uint32_t a) noexcept {
  const uint32_t t = static_cast<uint32_t>((static_cast<uint64_t>(a) * kBarrettMul) >> 38);
  return csubq(a - t * kQ);
}

// floor(n / q) for n < 2^23, by multiplication and shift (used by Compress).
inline constexpr uint64_t kDivQMul = ((uint64_t{1} << 40) + kQ - 1) / kQ;

[[nodiscard]] constexpr uint32_t div_q(uint32_t n) noexcept {
  return static_cast<uint32_t>((static_cast<uint64_t>(n) * kDivQMul) >> 40);
}

// Montgomery arithmetic with R = 2^16.
inline constexpr uint32_t kMontR = 1U << 16;
// -q^{-1} mod 2^16, found by Newton iteration on q^{-1} mod 2^16.
[[nodiscard]] consteval uint32_t neg_qinv() noexcept {
  uint32_t inv = 1;
  for (int i = 0; i < 5; ++i) {
    inv = (inv * (2U - kQ * inv)) & 0xFFFFU;
  }
  return (0x10000U - inv) & 0xFFFFU;
}
inline constexpr uint32_t kNegQInv = neg_qinv();
static_assert(((kQ * kNegQInv) & 0xFFFFU) == 0xFFFFU, "q * (-q^-1) == -1 mod 2^16");

// REDC: a < q * 2^16 -> a * R^{-1} mod q, result in [0, 2q) (not fully reduced).
[[nodiscard]] constexpr uint32_t montgomery_reduce_lazy(uint32_t a) noexcept {
  const uint32_t m = (a * kNegQInv) & 0xFFFFU;
  // a + m * q < q * 2^17 < 2^32
  return (a + m * kQ) >> 16;
}

[[nodiscard]] constexpr uint16_t montgomery_reduce(uint32_t a) noexcept {
  return csubq(montgomery_reduce_lazy(a));
}

// Plain modular helpers for x, y in [0, q).
[[nodiscard]] constexpr uint16_t add_mod(uint16_t x, uint16_t y) noexcept {
  return csubq(static_cast<uint32_t>(x) + y);
}
[[nodiscard]] constexpr uint16_t sub_mod(uint16_t x, uint16_t y) noexcept {
  return csubq(static_cast<uint32_t>(x) + kQ - y);
}
[[nodiscard]] constexpr uint16_t mul_mod(uint16_t x, uint16_t y) noexcept {
  return barrett_reduce(static_cast<uint32_t>(x) * y);
}

// x^e mod q for compile-time table generation only (public constants).
[[nodiscard]] consteval uint16_t pow_mod(uint32_t x, uint32_t e) noexcept {
  uint32_t r = 1;
  x %= kQ;
  while (e != 0) {
    if ((e & 1U) != 0) {
      r = (r * x) % kQ;
    }
    x = (x * x) % kQ;
    e >>= 1;
  }
  return static_cast<uint16_t>(r);
}

}  // namespace pq::mlkem::detail
