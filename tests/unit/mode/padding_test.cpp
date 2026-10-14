#include "mode/padding.hpp"

#include <gtest/gtest.h>

#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace {
TEST(Padding, AllLengthsAndBlockSizes) {
  for (const size_t block : {1U, 8U, 16U, 255U}) {
    for (size_t n = 0; n <= block * 2; ++n) {
      pq::SecureBytes message(n);
      for (size_t i = 0; i < n; ++i) message[i] = static_cast<uint8_t>(i);
      const auto padded = pq::mode::detail::pkcs7_pad(message, block);
      EXPECT_EQ(padded.size() % block, 0U);
      EXPECT_GT(padded.size(), n);
      EXPECT_TRUE(pq::ct_equal(padded.view().first(n), message));
      const auto length = pq::mode::detail::pkcs7_unpadded_size(padded, block);
      ASSERT_TRUE(length);
      EXPECT_EQ(*length, n);
      const size_t count = block - n % block;
      for (size_t i = n; i < padded.size(); ++i) {
        EXPECT_EQ(padded[i], count);
      }
    }
  }
}

TEST(Padding, RejectsEveryCorruptedPaddingPosition) {
  for (size_t count = 1; count <= 16; ++count) {
    const pq::SecureBytes message(16 - count);
    const auto padded = pq::mode::detail::pkcs7_pad(message, 16);
    for (size_t i = message.size(); i < 16; ++i) {
      auto bad = padded.clone();
      // A zero final byte is always invalid; a changed earlier padding byte
      // must fail even though the unchanged final byte specifies a valid count.
      bad[i] = 0;
      EXPECT_FALSE(pq::mode::detail::pkcs7_unpadded_size(bad, 16));
    }
  }
  pq::SecureBytes block(16);
  for (uint32_t value = 17; value <= 255; ++value) {
    block[15] = static_cast<uint8_t>(value);
    EXPECT_FALSE(pq::mode::detail::pkcs7_unpadded_size(block, 16));
  }
}

TEST(Padding, RejectsInvalidPublicLengths) {
  const pq::SecureBytes input(17);
  for (const size_t block : {0U, 256U}) {
    EXPECT_THROW((void)pq::mode::detail::pkcs7_pad(input, block), pq::Error);
    EXPECT_THROW((void)pq::mode::detail::pkcs7_unpadded_size(input, block), pq::Error);
  }
  EXPECT_THROW((void)pq::mode::detail::pkcs7_unpadded_size({}, 16), pq::Error);
  EXPECT_THROW((void)pq::mode::detail::pkcs7_unpadded_size(input, 16), pq::Error);
}
}  // namespace
