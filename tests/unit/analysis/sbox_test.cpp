#include "analysis/sbox/sbox.hpp"

#include <gtest/gtest.h>

#include <array>
#include <bit>
#include <numeric>

#include "pq/error.hpp"

namespace pq::analysis {
namespace {

TEST(SboxAnalysis, IdentityHasExactDiagonalDdtAndLat) {
  std::array<uint8_t, 256> identity{};
  std::iota(identity.begin(), identity.end(), uint8_t{0});
  const auto result = analyze_sbox(identity);
  EXPECT_TRUE(result.permutation);
  EXPECT_EQ(result.differential_uniformity, 256);
  EXPECT_EQ(result.nonlinearity, 0);
  for (size_t a = 0; a < 256; ++a) {
    for (size_t b = 0; b < 256; ++b) {
      EXPECT_EQ(result.ddt[a][b], a == b ? 256 : 0);
      EXPECT_EQ(result.lat[a][b], a == b ? 128 : 0);
    }
  }
}

TEST(SboxAnalysis, AffineTranslationKeepsDdtAndChangesLatSigns) {
  std::array<uint8_t, 256> mapping{};
  for (uint32_t x = 0; x < 256; ++x) {
    mapping[x] = static_cast<uint8_t>(x ^ 0x59U);
  }
  const auto result = analyze_sbox(mapping);
  EXPECT_TRUE(result.permutation);
  EXPECT_EQ(result.nonlinearity, 0);
  for (uint32_t a = 0; a < 256; ++a) {
    EXPECT_EQ(result.ddt[a][a], 256);
    EXPECT_EQ(result.lat[a][a], (std::popcount(a & 0x59U) & 1) != 0 ? -128 : 128);
  }
}

TEST(SboxAnalysis, NonPermutationIncludesConstantComponentInNonlinearity) {
  std::array<uint8_t, 256> mapping{};
  for (uint32_t x = 0; x < 256; ++x) {
    mapping[x] = static_cast<uint8_t>((x & 1U) & ((x >> 1) & 1U));
  }
  const auto result = analyze_sbox(mapping);
  EXPECT_FALSE(result.permutation);
  EXPECT_EQ(result.nonlinearity, 0);
  EXPECT_EQ(result.lat[0][1], 64);
  EXPECT_EQ(result.ddt[1][0], 128);
  EXPECT_EQ(result.ddt[1][1], 128);
  for (size_t a = 0; a < 256; ++a) {
    EXPECT_EQ(std::accumulate(result.ddt[a].begin(), result.ddt[a].end(), uint32_t{0}), 256);
  }
}

TEST(SboxAnalysis, WalshTransformMatchesDirectParityDefinition) {
  // An algebraic test function, not a cryptographic known-answer vector.
  std::array<uint8_t, 256> mapping{};
  for (uint32_t x = 0; x < 256; ++x) {
    mapping[x] = static_cast<uint8_t>((x * x) & 255U);
  }
  const auto result = analyze_sbox(mapping);
  for (const uint32_t a : {0U, 1U, 7U, 63U, 255U}) {
    for (const uint32_t b : {0U, 1U, 9U, 57U, 255U}) {
      int32_t matches = 0;
      for (uint32_t x = 0; x < 256; ++x) {
        matches += ((std::popcount(a & x) ^ std::popcount(b & mapping[x])) & 1) == 0;
      }
      EXPECT_EQ(result.lat[a][b], matches - 128);
    }
  }
}

TEST(SboxAnalysis, RequiresFullByteMapping) {
  EXPECT_THROW((void)analyze_sbox(Bytes(255)), Error);
  EXPECT_THROW((void)analyze_sbox(Bytes(257)), Error);
}

}  // namespace
}  // namespace pq::analysis
