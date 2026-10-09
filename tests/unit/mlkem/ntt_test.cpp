#include "kem/mlkem/ntt.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>

namespace {

using namespace pq::mlkem;
using namespace pq::mlkem::detail;

Poly random_poly(std::mt19937& rng) {
  std::uniform_int_distribution<uint32_t> dist(0, kQ - 1);
  Poly p;
  for (auto& x : p.c) {
    x = static_cast<uint16_t>(dist(rng));
  }
  return p;
}

// Multiplication in Z_q[X]/(X^256 + 1).
Poly schoolbook(const Poly& f, const Poly& g) {
  std::array<int64_t, kN> acc{};
  for (size_t i = 0; i < kN; ++i) {
    for (size_t j = 0; j < kN; ++j) {
      const int64_t prod = static_cast<int64_t>(f[i]) * g[j];
      if (i + j < kN) {
        acc[i + j] += prod;
      } else {
        acc[i + j - kN] -= prod;
      }
    }
  }
  Poly h;
  for (size_t i = 0; i < kN; ++i) {
    h[i] = static_cast<uint16_t>(((acc[i] % kQ) + kQ) % kQ);
  }
  return h;
}

TEST(MlKemNtt, ZetasMatchFips203AppendixA) {
  // FIPS 203, Appendix A: zeta^BitRev7(i) mod q.
  constexpr std::array<uint16_t, 128> kAppendixA = {
      1,    1729, 2580, 3289, 2642, 630,  1897, 848,  1062, 1919, 193,  797,  2786, 3260, 569,
      1746, 296,  2447, 1339, 1476, 3046, 56,   2240, 1333, 1426, 2094, 535,  2882, 2393, 2879,
      1974, 821,  289,  331,  3253, 1756, 1197, 2304, 2277, 2055, 650,  1977, 2513, 632,  2865,
      33,   1320, 1915, 2319, 1435, 807,  452,  1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
      2474, 3110, 1227, 910,  17,   2761, 583,  2649, 1637, 723,  2288, 1100, 1409, 2662, 3281,
      233,  756,  2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,  1461, 2687, 939,  2308,
      2437, 2388, 733,  2337, 268,  641,  1584, 2298, 2037, 3220, 375,  2549, 2090, 1645, 1063,
      319,  2773, 757,  2099, 561,  2466, 2594, 2804, 1092, 403,  1026, 1143, 2150, 2775, 886,
      1722, 1212, 1874, 1029, 2110, 2935, 885,  2154};
  EXPECT_EQ(kZetas, kAppendixA);
  // Second table of Appendix A: zeta^(2 BitRev7(i) + 1) = +-zeta^BitRev7(64 + i / 2).
  for (size_t i = 0; i < 128; ++i) {
    const uint16_t base = kAppendixA[64 + i / 2];
    EXPECT_EQ(kGammas[i], i % 2 == 0 ? base : kQ - base) << i;
  }
}

TEST(MlKemNtt, RefRoundTrip) {
  std::mt19937 rng(1);
  for (int iter = 0; iter < 100; ++iter) {
    const Poly f = random_poly(rng);
    Poly g = f;
    ntt_ref(g);
    inv_ntt_ref(g);
    ASSERT_EQ(g, f);
  }
}

TEST(MlKemNtt, OptimizedRoundTrip) {
  std::mt19937 rng(2);
  for (int iter = 0; iter < 100; ++iter) {
    const Poly f = random_poly(rng);
    Poly g = f;
    ntt(g);
    inv_ntt(g);
    ASSERT_EQ(g, f);
  }
}

TEST(MlKemNtt, OptimizedMatchesReference) {
  std::mt19937 rng(3);
  for (int iter = 0; iter < 200; ++iter) {
    const Poly f = random_poly(rng);
    const Poly g = random_poly(rng);
    Poly a = f;
    Poly b = f;
    ntt(a);
    ntt_ref(b);
    ASSERT_EQ(a, b);
    inv_ntt(a);
    inv_ntt_ref(b);
    ASSERT_EQ(a, b);
    Poly h1;
    Poly h2;
    multiply_ntts(h1, f, g);
    multiply_ntts_ref(h2, f, g);
    ASSERT_EQ(h1, h2);
  }
}

TEST(MlKemNtt, ExtremeCoefficients) {
  // All coefficients q - 1 maximize the lazy bounds.
  Poly f;
  f.c.fill(kQ - 1);
  Poly a = f;
  Poly b = f;
  ntt(a);
  ntt_ref(b);
  EXPECT_EQ(a, b);
  inv_ntt(a);
  EXPECT_EQ(a, f);
  Poly h1;
  Poly h2;
  multiply_ntts(h1, f, f);
  multiply_ntts_ref(h2, f, f);
  EXPECT_EQ(h1, h2);
}

TEST(MlKemNtt, MultiplicationMatchesSchoolbook) {
  std::mt19937 rng(4);
  for (int iter = 0; iter < 20; ++iter) {
    const Poly f = random_poly(rng);
    const Poly g = random_poly(rng);
    Poly fh = f;
    Poly gh = g;
    ntt(fh);
    ntt(gh);
    Poly h;
    multiply_ntts(h, fh, gh);
    inv_ntt(h);
    ASSERT_EQ(h, schoolbook(f, g));

    Poly fr = f;
    Poly gr = g;
    ntt_ref(fr);
    ntt_ref(gr);
    Poly hr;
    multiply_ntts_ref(hr, fr, gr);
    inv_ntt_ref(hr);
    ASSERT_EQ(hr, schoolbook(f, g));
  }
}

}  // namespace
