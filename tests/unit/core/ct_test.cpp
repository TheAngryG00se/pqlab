#include "pq/ct.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include "pq/error.hpp"

namespace {

TEST(Ct, IsZeroMask) {
  EXPECT_EQ(pq::ct_is_zero_mask(0), 0xFF);
  EXPECT_EQ(pq::ct_is_zero_mask(1), 0x00);
  EXPECT_EQ(pq::ct_is_zero_mask(0x80000000U), 0x00);
  EXPECT_EQ(pq::ct_is_zero_mask(0xFFFFFFFFU), 0x00);
}

TEST(Ct, EqualMask) {
  const std::array<uint8_t, 4> a{1, 2, 3, 4};
  std::array<uint8_t, 4> b = a;
  EXPECT_EQ(pq::ct_equal_mask(a, b), 0xFF);
  EXPECT_TRUE(pq::ct_equal(a, b));
  for (size_t i = 0; i < b.size(); ++i) {
    for (int bit = 0; bit < 8; ++bit) {
      b = a;
      b[i] ^= static_cast<uint8_t>(1U << bit);
      EXPECT_EQ(pq::ct_equal_mask(a, b), 0x00);
      EXPECT_FALSE(pq::ct_equal(a, b));
    }
  }
}

TEST(Ct, DifferentLengthsAreUnequal) {
  const std::array<uint8_t, 3> a{1, 2, 3};
  const std::array<uint8_t, 2> b{1, 2};
  EXPECT_FALSE(pq::ct_equal(a, b));
  EXPECT_TRUE(pq::ct_equal(pq::ByteView{}, pq::ByteView{}));
}

TEST(Ct, Select) {
  const std::array<uint8_t, 3> a{0xAA, 0xBB, 0xCC};
  const std::array<uint8_t, 3> b{0x11, 0x22, 0x33};
  std::array<uint8_t, 3> out{};
  pq::ct_select(out, a, b, 0xFF);
  EXPECT_EQ(out, a);
  pq::ct_select(out, a, b, 0x00);
  EXPECT_EQ(out, b);
}

TEST(Ct, SelectLengthMismatchThrows) {
  const std::array<uint8_t, 3> a{};
  const std::array<uint8_t, 2> b{};
  std::array<uint8_t, 3> out{};
  EXPECT_THROW(pq::ct_select(out, a, b, 0xFF), pq::Error);
}

}  // namespace
