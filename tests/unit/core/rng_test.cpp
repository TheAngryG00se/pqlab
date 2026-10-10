#include "pq/rng.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "hash/shake.hpp"

namespace {

TEST(DeterministicRng, StreamIsShake256OfSeed) {
  const std::array<uint8_t, 4> seed{1, 2, 3, 4};
  pq::DeterministicRng rng(seed);

  std::vector<uint8_t> got(300);
  rng.fill(got);

  std::vector<uint8_t> want(300);
  pq::hash::shake256(want, seed);
  EXPECT_EQ(got, want);
}

TEST(DeterministicRng, SuccessiveFillsContinueTheStream) {
  const std::array<uint8_t, 2> seed{9, 9};
  pq::DeterministicRng a(seed);
  pq::DeterministicRng b(seed);

  std::vector<uint8_t> whole(100);
  a.fill(whole);

  std::vector<uint8_t> parts(100);
  b.fill(std::span(parts).first(37));
  b.fill(std::span(parts).subspan(37));
  EXPECT_EQ(whole, parts);
}

TEST(DeterministicRng, DifferentSeedsDiffer) {
  const std::array<uint8_t, 1> s1{1};
  const std::array<uint8_t, 1> s2{2};
  pq::DeterministicRng a(s1);
  pq::DeterministicRng b(s2);
  std::array<uint8_t, 32> x{};
  std::array<uint8_t, 32> y{};
  a.fill(x);
  b.fill(y);
  EXPECT_NE(x, y);
}

TEST(SystemRng, FillsRequestedLengthAndIsNotConstant) {
  pq::SystemRng rng;
  std::array<uint8_t, 64> a{};
  std::array<uint8_t, 64> b{};
  rng.fill(a);
  rng.fill(b);
  // 2^-512 chance of a false failure.
  EXPECT_NE(a, b);
  EXPECT_FALSE(std::all_of(a.begin(), a.end(), [](uint8_t v) { return v == 0; }));
}

TEST(SystemRng, LargeRequestAndEmptyRequest) {
  pq::SystemRng rng;
  std::vector<uint8_t> big(1 << 20);
  rng.fill(big);
  EXPECT_FALSE(std::all_of(big.begin(), big.end(), [](uint8_t v) { return v == 0; }));
  rng.fill(std::span<uint8_t>{});
}

}  // namespace
