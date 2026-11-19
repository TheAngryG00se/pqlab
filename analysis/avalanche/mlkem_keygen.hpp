#pragma once

#include <array>
#include <cstdint>

#include "pq/kem.hpp"

namespace pq::analysis {

struct KeygenDistances {
  uint64_t pk_bits = 0;
  uint64_t dk_bits = 0;
};

// Sum of Hamming distances over paired trials for the two halves of d || z, in that order.
using KeygenAvalanche = std::array<KeygenDistances, 2>;
[[nodiscard]] KeygenAvalanche mlkem_keygen_avalanche(const Kem& kem, uint32_t samples);

}  // namespace pq::analysis
