#include "kem/mlkem/sampling.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "hash/shake.hpp"

namespace {

using namespace pq::mlkem;
using namespace pq::mlkem::detail;

// FIPS 203, Algorithm 7 literally: 3-byte squeezes.
Poly sample_ntt_literal(const std::array<uint8_t, 32>& rho, uint8_t j, uint8_t i) {
  pq::hash::Shake128 xof;
  std::vector<uint8_t> b(rho.begin(), rho.end());
  b.push_back(j);
  b.push_back(i);
  xof.absorb(b);
  Poly a;
  size_t n = 0;
  while (n < kN) {
    std::array<uint8_t, 3> c{};
    xof.squeeze(c);
    const uint32_t d1 = c[0] + 256U * (c[1] % 16);
    const uint32_t d2 = c[1] / 16U + 16U * c[2];
    if (d1 < kQ) {
      a[n++] = static_cast<uint16_t>(d1);
    }
    if (d2 < kQ && n < kN) {
      a[n++] = static_cast<uint16_t>(d2);
    }
  }
  return a;
}

TEST(MlKemSampling, SampleNttMatchesLiteralAlgorithm) {
  std::array<uint8_t, 32> rho{};
  for (int seed = 0; seed < 20; ++seed) {
    for (size_t k = 0; k < rho.size(); ++k) {
      rho[k] = static_cast<uint8_t>(seed * 37 + k);
    }
    Poly a;
    sample_ntt(a, rho, static_cast<uint8_t>(seed % 4), static_cast<uint8_t>(seed / 4));
    ASSERT_EQ(
        a, sample_ntt_literal(rho, static_cast<uint8_t>(seed % 4), static_cast<uint8_t>(seed / 4)));
    for (auto x : a.c) {
      ASSERT_LT(x, kQ);
    }
  }
}

template <unsigned Eta>
void check_cbd() {
  std::array<uint8_t, 32> s{};
  s[0] = static_cast<uint8_t>(Eta);
  std::array<long, 2 * Eta + 1> hist{};
  for (uint8_t nonce = 0; nonce < 64; ++nonce) {
    std::array<uint8_t, 64 * Eta> buf{};
    prf<Eta>(buf, s, nonce);
    Poly f;
    sample_poly_cbd<Eta>(f, buf);
    for (auto x : f.c) {
      // Centered value in [-eta, eta].
      const int v = x <= Eta ? static_cast<int>(x) : static_cast<int>(x) - static_cast<int>(kQ);
      ASSERT_GE(v, -static_cast<int>(Eta));
      ASSERT_LE(v, static_cast<int>(Eta));
      ++hist[static_cast<size_t>(v + static_cast<int>(Eta))];
    }
  }
  // Binomial shape: the centre is the most frequent value and the tails are
  // the least frequent (64 * 256 samples).
  for (size_t k = 0; k < Eta; ++k) {
    EXPECT_LT(hist[k], hist[k + 1]);
    EXPECT_GT(hist[Eta + k], hist[Eta + k + 1]);
  }
}

TEST(MlKemSampling, CbdRangeAndShape) {
  check_cbd<2>();
  check_cbd<3>();
}

TEST(MlKemSampling, CbdBitLayout) {
  // eta = 2, first byte 0b0000'0111: coefficient 0 has x = 1 + 1, y = 1 + 0 -> 1.
  // FIPS 203, Algorithm 8, lines 3-5.
  std::array<uint8_t, 128> b{};
  b[0] = 0x07;
  Poly f;
  sample_poly_cbd<2>(f, b);
  EXPECT_EQ(f[0], 1);
  EXPECT_EQ(f[1], 0);
  b[0] = 0x0C;  // x = 0, y = 2 -> -2
  sample_poly_cbd<2>(f, b);
  EXPECT_EQ(f[0], kQ - 2);
}

}  // namespace
