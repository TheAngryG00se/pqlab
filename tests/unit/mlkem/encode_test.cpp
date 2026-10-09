#include "kem/mlkem/encode.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <vector>

namespace {

using namespace pq::mlkem;
using namespace pq::mlkem::detail;

template <unsigned D>
void check_round_trip(std::mt19937& rng) {
  const uint32_t modulus = D == 12 ? kQ : (1U << D);
  std::uniform_int_distribution<uint32_t> dist(0, modulus - 1);
  for (int iter = 0; iter < 50; ++iter) {
    Poly f;
    for (auto& x : f.c) {
      x = static_cast<uint16_t>(dist(rng));
    }
    std::array<uint8_t, 32 * D> bytes{};
    byte_encode<D>(bytes, f);
    Poly g;
    byte_decode<D>(g, bytes);
    ASSERT_EQ(f, g) << "d = " << D;
  }
}

TEST(MlKemEncode, RoundTripAllWidths) {
  std::mt19937 rng(5);
  check_round_trip<1>(rng);
  check_round_trip<4>(rng);
  check_round_trip<5>(rng);
  check_round_trip<10>(rng);
  check_round_trip<11>(rng);
  check_round_trip<12>(rng);
}

TEST(MlKemEncode, BitOrderIsLittleEndian) {
  // FIPS 203, Algorithm 3: bit i of the stream is bit (i mod 8) of byte i / 8.
  Poly f;
  f[0] = 1;  // bit 0
  f[1] = 1;  // bit 12
  std::array<uint8_t, 384> bytes{};
  byte_encode<12>(bytes, f);
  EXPECT_EQ(bytes[0], 0x01);
  EXPECT_EQ(bytes[1], 0x10);
  EXPECT_EQ(bytes[2], 0x00);
}

TEST(MlKemEncode, Decode12ReducesModQ) {
  std::array<uint8_t, 384> bytes{};
  bytes.fill(0xFF);  // every 12-bit value is 4095
  Poly f;
  byte_decode<12>(f, bytes);
  for (auto x : f.c) {
    EXPECT_EQ(x, 4095 % kQ);
  }
}

// round(2^d x / q) computed with exact integer arithmetic (test only).
uint32_t compress_exact(uint32_t x, unsigned d) {
  return ((x << (d + 1)) + kQ) / (2 * kQ) % (1U << d);
}

uint32_t decompress_exact(uint32_t y, unsigned d) {
  return (2 * kQ * y + (1U << d)) / (1U << (d + 1));
}

template <unsigned D>
void check_compress() {
  for (uint32_t x = 0; x < kQ; ++x) {
    ASSERT_EQ(compress<D>(static_cast<uint16_t>(x)), compress_exact(x, D)) << D << " " << x;
  }
  for (uint32_t y = 0; y < (1U << D); ++y) {
    ASSERT_EQ(decompress<D>(static_cast<uint16_t>(y)), decompress_exact(y, D)) << D << " " << y;
    // FIPS 203, Section 4.2.1: Compress_d(Decompress_d(y)) = y.
    ASSERT_EQ(compress<D>(decompress<D>(static_cast<uint16_t>(y))), y) << D << " " << y;
  }
}

TEST(MlKemEncode, CompressDecompressExhaustive) {
  check_compress<1>();
  check_compress<4>();
  check_compress<5>();
  check_compress<10>();
  check_compress<11>();
}

}  // namespace
