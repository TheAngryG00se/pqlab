#pragma once

#include <array>
#include <cstdint>

#include "pq/secure_bytes.hpp"

namespace pq::analysis {

// Tables contain public S-box values, never secret-dependent substitutions.
struct SboxAnalysis {
  std::array<std::array<uint16_t, 256>, 256> ddt{};
  // LAT[a][b] = #{x : parity(a & x) == parity(b & S(x))} - 128.
  // The corresponding Walsh coefficient is 2 * LAT[a][b].
  std::array<std::array<int16_t, 256>, 256> lat{};
  uint16_t differential_uniformity = 0;
  uint16_t nonlinearity = 0;
  uint16_t max_absolute_lat = 0;
  bool permutation = false;
};

// Accepts every 8 -> 8 bit mapping (including non-permutations), exactly 256 bytes.
[[nodiscard]] SboxAnalysis analyze_sbox(ByteView table);

}  // namespace pq::analysis
