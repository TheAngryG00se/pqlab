#include "pq/secure_bytes.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>

namespace {

TEST(SecureBytes, ConstructZeroed) {
  pq::SecureBytes s(16);
  ASSERT_EQ(s.size(), 16U);
  for (uint8_t b : s) {
    EXPECT_EQ(b, 0);
  }
}

TEST(SecureBytes, CopyFromViewAndClone) {
  const std::array<uint8_t, 3> src{7, 8, 9};
  pq::SecureBytes s(src);
  pq::SecureBytes c = s.clone();
  ASSERT_EQ(c.size(), 3U);
  EXPECT_EQ(c[0], 7);
  EXPECT_EQ(c[2], 9);
  EXPECT_NE(c.data(), s.data());
}

TEST(SecureBytes, MoveLeavesSourceEmpty) {
  pq::SecureBytes s(8);
  s[0] = 42;
  pq::SecureBytes t = std::move(s);
  EXPECT_EQ(t.size(), 8U);
  EXPECT_EQ(t[0], 42);
  EXPECT_TRUE(s.empty());  // NOLINT(bugprone-use-after-move): moved-from state is specified
  EXPECT_EQ(s.data(), nullptr);
}

TEST(SecureBytes, SecureZero) {
  std::array<uint8_t, 5> buf{1, 2, 3, 4, 5};
  pq::secure_zero(buf);
  for (uint8_t b : buf) {
    EXPECT_EQ(b, 0);
  }
}

TEST(SecureBytes, EmptyBuffer) {
  pq::SecureBytes s(0);
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.view().size(), 0U);
}

}  // namespace
