#include "sbox.hpp"

#include <algorithm>
#include <bit>
#include <cstdlib>

#include "pq/error.hpp"

namespace pq::analysis {

// Carlet, Boolean Functions for Cryptography and Coding Theory, Sections 2.3.6,
// 3.2.3 and 3.4.1: Walsh transform, vectorial nonlinearity and differential uniformity.
SboxAnalysis analyze_sbox(ByteView table) {
  if (table.size() != 256) {
    throw Error("S-box analysis requires exactly 256 public entries");
  }
  SboxAnalysis result;
  std::array<uint16_t, 256> multiplicity{};
  for (uint8_t value : table) {
    ++multiplicity[value];
  }
  result.permutation = std::all_of(multiplicity.begin(), multiplicity.end(),
                                   [](uint16_t count) { return count == 1; });
  for (uint32_t a = 0; a < 256; ++a) {
    for (uint32_t x = 0; x < 256; ++x) {
      ++result.ddt[a][table[x] ^ table[x ^ a]];
    }
    if (a != 0) {
      result.differential_uniformity =
          std::max(result.differential_uniformity,
                   *std::max_element(result.ddt[a].begin(), result.ddt[a].end()));
    }
  }
  for (uint32_t b = 0; b < 256; ++b) {
    std::array<int32_t, 256> walsh{};
    for (uint32_t x = 0; x < 256; ++x) {
      walsh[x] = 1 - 2 * (std::popcount(b & table[x]) & 1);
    }
    // The unnormalised fast Walsh-Hadamard transform, with public butterfly indices.
    for (uint32_t stride = 1; stride < 256; stride *= 2) {
      for (uint32_t base = 0; base < 256; base += 2 * stride) {
        for (uint32_t offset = 0; offset < stride; ++offset) {
          const int32_t left = walsh[base + offset];
          const int32_t right = walsh[base + offset + stride];
          walsh[base + offset] = left + right;
          walsh[base + offset + stride] = left - right;
        }
      }
    }
    for (uint32_t a = 0; a < 256; ++a) {
      result.lat[a][b] = static_cast<int16_t>(walsh[a] / 2);
      if (b != 0) {
        result.max_absolute_lat =
            std::max(result.max_absolute_lat, static_cast<uint16_t>(std::abs(result.lat[a][b])));
      }
    }
  }
  result.nonlinearity = static_cast<uint16_t>(128 - result.max_absolute_lat);
  return result;
}

}  // namespace pq::analysis
