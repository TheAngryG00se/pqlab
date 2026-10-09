#pragma once

#include <array>
#include <cstdint>

#include "kem/mlkem/poly.hpp"

namespace pq::mlkem::detail {

// zeta^BitRev7(i) mod q, i = 0..127 (FIPS 203, Appendix A).
extern const std::array<uint16_t, 128> kZetas;
// zeta^(2 BitRev7(i) + 1) mod q, i = 0..127 (FIPS 203, Appendix A).
extern const std::array<uint16_t, 128> kGammas;

// Optimized versions: Montgomery multiplication with lazy reduction.
// Inputs and outputs are canonical (coefficients in [0, q)).
void ntt(Poly& f) noexcept;
void inv_ntt(Poly& f) noexcept;
void multiply_ntts(Poly& h, const Poly& f, const Poly& g) noexcept;

// Reference versions: the algorithms literally, with a full Barrett reduction
// after every operation. Kept for tests and for the before/after benchmark.
void ntt_ref(Poly& f) noexcept;
void inv_ntt_ref(Poly& f) noexcept;
void multiply_ntts_ref(Poly& h, const Poly& f, const Poly& g) noexcept;

}  // namespace pq::mlkem::detail
