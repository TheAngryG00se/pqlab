#pragma once

// Vector and matrix operations over T_q (FIPS 203, Sections 2.4.7 and 2.4.8).

#include <cstddef>
#include <cstdint>
#include <span>

#include "kem/mlkem/encode.hpp"
#include "kem/mlkem/ntt.hpp"
#include "kem/mlkem/poly.hpp"

namespace pq::mlkem::detail {

template <size_t K>
void polyvec_ntt(PolyVec<K>& v) noexcept {
  for (auto& p : v) {
    ntt(p);
  }
}

template <size_t K>
void polyvec_inv_ntt(PolyVec<K>& v) noexcept {
  for (auto& p : v) {
    inv_ntt(p);
  }
}

template <size_t K>
void polyvec_add(PolyVec<K>& r, const PolyVec<K>& a, const PolyVec<K>& b) noexcept {
  for (size_t i = 0; i < K; ++i) {
    poly_add(r[i], a[i], b[i]);
  }
}

// r = a^T o b = sum_i a[i] * b[i] in T_q.
template <size_t K>
void polyvec_dot(Poly& r, const PolyVec<K>& a, const PolyVec<K>& b) noexcept {
  Poly tmp;
  multiply_ntts(r, a[0], b[0]);
  for (size_t i = 1; i < K; ++i) {
    multiply_ntts(tmp, a[i], b[i]);
    poly_add(r, r, tmp);
  }
}

// r = A o v (transpose = false) or A^T o v (transpose = true).
template <size_t K>
void matrix_mul(PolyVec<K>& r, const PolyMat<K>& a, const PolyVec<K>& v, bool transpose) noexcept {
  Poly tmp;
  for (size_t i = 0; i < K; ++i) {
    for (size_t j = 0; j < K; ++j) {
      const Poly& aij = transpose ? a[j][i] : a[i][j];  // public layout choice
      if (j == 0) {
        multiply_ntts(r[i], aij, v[j]);
      } else {
        multiply_ntts(tmp, aij, v[j]);
        poly_add(r[i], r[i], tmp);
      }
    }
  }
}

template <unsigned D, size_t K>
void polyvec_encode(std::span<uint8_t, 32 * D * K> out, const PolyVec<K>& v) noexcept {
  for (size_t i = 0; i < K; ++i) {
    byte_encode<D>(out.subspan(32 * D * i).template first<32 * D>(), v[i]);
  }
}

template <unsigned D, size_t K>
void polyvec_decode(PolyVec<K>& v, std::span<const uint8_t, 32 * D * K> in) noexcept {
  for (size_t i = 0; i < K; ++i) {
    byte_decode<D>(v[i], in.subspan(32 * D * i).template first<32 * D>());
  }
}

}  // namespace pq::mlkem::detail
