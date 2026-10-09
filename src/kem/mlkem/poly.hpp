#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "kem/mlkem/params.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::mlkem::detail {

// Element of R_q or T_q: 256 coefficients in [0, q) (FIPS 203, Section 2.4.4).
// Polynomials often hold secrets (s, e, y, mu), so every Poly is wiped on
// destruction.
struct Poly {
  std::array<uint16_t, kN> c{};

  Poly() = default;
  Poly(const Poly&) = default;
  Poly& operator=(const Poly&) = default;
  ~Poly() { secure_zero(c.data(), sizeof(c)); }

  uint16_t& operator[](size_t i) noexcept { return c[i]; }
  const uint16_t& operator[](size_t i) const noexcept { return c[i]; }
  bool operator==(const Poly& other) const = default;
};

template <size_t K>
using PolyVec = std::array<Poly, K>;

template <size_t K>
using PolyMat = std::array<PolyVec<K>, K>;

}  // namespace pq::mlkem::detail
