// Exhaustive checks of the reduction helpers over their documented input ranges.

#include "kem/mlkem/reduce.hpp"

#include <gtest/gtest.h>

#include <cstdint>

namespace {

using namespace pq::mlkem;
using namespace pq::mlkem::detail;

TEST(MlKemReduce, CsubqAllInputs) {
  for (uint32_t x = 0; x < 2 * kQ; ++x) {
    ASSERT_EQ(csubq(x), x % kQ) << x;
  }
}

TEST(MlKemReduce, BarrettBelow2Pow26) {
  for (uint32_t a = 0; a < (1U << 26); ++a) {
    if (barrett_reduce(a) != a % kQ) {
      FAIL() << "a = " << a;
    }
  }
}

TEST(MlKemReduce, DivQBelow2Pow23) {
  for (uint32_t n = 0; n < (1U << 23); ++n) {
    if (div_q(n) != n / kQ) {
      FAIL() << "n = " << n;
    }
  }
}

TEST(MlKemReduce, MontgomeryFullRange) {
  // R^{-1} mod q: R * Rinv == 1 mod q.
  uint32_t r_inv = 0;
  for (uint32_t x = 1; x < kQ; ++x) {
    if ((kMontR % kQ) * x % kQ == 1) {
      r_inv = x;
      break;
    }
  }
  ASSERT_NE(r_inv, 0U);
  const uint32_t limit = kQ << 16;
  for (uint32_t a = 0; a < limit; a += 7) {
    const uint32_t lazy = montgomery_reduce_lazy(a);
    const uint32_t expected = static_cast<uint32_t>((static_cast<uint64_t>(a) * r_inv) % kQ);
    if (lazy >= 2 * kQ || lazy % kQ != expected) {
      FAIL() << "a = " << a;
    }
  }
  EXPECT_EQ(montgomery_reduce(limit - 1), ((static_cast<uint64_t>(limit) - 1) * r_inv) % kQ);
}

TEST(MlKemReduce, ModularHelpers) {
  for (uint32_t x = 0; x < kQ; x += 13) {
    for (uint32_t y = 0; y < kQ; y += 11) {
      const auto a = static_cast<uint16_t>(x);
      const auto b = static_cast<uint16_t>(y);
      ASSERT_EQ(add_mod(a, b), (x + y) % kQ);
      ASSERT_EQ(sub_mod(a, b), (x + kQ - y) % kQ);
      ASSERT_EQ(mul_mod(a, b), (x * y) % kQ);
    }
  }
}

}  // namespace
