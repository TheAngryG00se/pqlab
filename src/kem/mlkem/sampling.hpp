#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "kem/mlkem/poly.hpp"

namespace pq::mlkem::detail {

// FIPS 203, Algorithm 7 (SampleNTT) on input B = rho || j || i.
// Rejection sampling on public data (rho is part of ek), so the data-dependent
// loop does not leak secrets.
void sample_ntt(Poly& a, std::span<const uint8_t, 32> rho, uint8_t j, uint8_t i);

// FIPS 203, Eq. (4.3): PRF_eta(s, b) = SHAKE256(s || b, 8 * 64 * eta).
template <unsigned Eta>
void prf(std::span<uint8_t, 64 * Eta> out, std::span<const uint8_t, 32> s, uint8_t b);

// FIPS 203, Algorithm 8 (SamplePolyCBD_eta). Constant time.
template <unsigned Eta>
void sample_poly_cbd(Poly& f, std::span<const uint8_t, 64 * Eta> b) noexcept;

}  // namespace pq::mlkem::detail
