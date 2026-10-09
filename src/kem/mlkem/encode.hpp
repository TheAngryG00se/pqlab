#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "kem/mlkem/poly.hpp"
#include "kem/mlkem/reduce.hpp"

namespace pq::mlkem::detail {

// FIPS 203, Algorithm 5 (ByteEncode_d). Coefficients must be < 2^d (d < 12)
// or < q (d = 12). Bits are packed little-endian (Algorithm 3, BitsToBytes).
template <unsigned D>
void byte_encode(std::span<uint8_t, 32 * D> out, const Poly& f) noexcept {
  static_assert(D >= 1 && D <= 12);
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < kN; ++i) {
    acc |= static_cast<uint32_t>(f[i]) << bits;
    bits += D;
    while (bits >= 8) {
      out[o++] = static_cast<uint8_t>(acc);
      acc >>= 8;
      bits -= 8;
    }
  }
}

// FIPS 203, Algorithm 6 (ByteDecode_d). For d = 12 the result is reduced mod q.
template <unsigned D>
void byte_decode(Poly& f, std::span<const uint8_t, 32 * D> in) noexcept {
  static_assert(D >= 1 && D <= 12);
  constexpr uint32_t kMask = (1U << D) - 1;
  uint32_t acc = 0;
  unsigned bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < kN; ++i) {
    while (bits < D) {
      acc |= static_cast<uint32_t>(in[o++]) << bits;
      bits += 8;
    }
    const uint32_t v = acc & kMask;
    acc >>= D;
    bits -= D;
    if constexpr (D == 12) {
      f[i] = csubq(v);  // v < 4096 < 2q
    } else {
      f[i] = static_cast<uint16_t>(v);
    }
  }
}

// FIPS 203, Eq. (4.7): Compress_d(x) = round(2^d x / q) mod 2^d, x in [0, q).
// round(2^d x / q) = floor((2^d x + (q - 1) / 2) / q) since q is odd; the
// division is a multiplication by a constant (no secret-dependent timing).
template <unsigned D>
[[nodiscard]] constexpr uint16_t compress(uint16_t x) noexcept {
  static_assert(D >= 1 && D < 12);
  // 2^11 * (q - 1) + (q - 1) / 2 < 2^23, the valid range of div_q.
  const uint32_t n = (static_cast<uint32_t>(x) << D) + (kQ - 1) / 2;
  return static_cast<uint16_t>(div_q(n) & ((1U << D) - 1));
}

// FIPS 203, Eq. (4.8): Decompress_d(y) = round(q y / 2^d), y in [0, 2^d).
template <unsigned D>
[[nodiscard]] constexpr uint16_t decompress(uint16_t y) noexcept {
  static_assert(D >= 1 && D < 12);
  return static_cast<uint16_t>((static_cast<uint32_t>(y) * kQ + (1U << (D - 1))) >> D);
}

template <unsigned D>
void compress_poly(Poly& f) noexcept {
  for (auto& x : f.c) {
    x = compress<D>(x);
  }
}

template <unsigned D>
void decompress_poly(Poly& f) noexcept {
  for (auto& x : f.c) {
    x = decompress<D>(x);
  }
}

}  // namespace pq::mlkem::detail
