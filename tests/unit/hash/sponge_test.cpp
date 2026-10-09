// Incremental absorb/squeeze must match the one-shot functions.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "hash/keccak.hpp"
#include "hash/sha3.hpp"
#include "hash/shake.hpp"
#include "pq/error.hpp"

namespace {

std::vector<uint8_t> pattern(size_t n) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; ++i) {
    v[i] = static_cast<uint8_t>(i * 31 + 7);
  }
  return v;
}

TEST(Sponge, ChunkedAbsorbMatchesOneShot) {
  // Lengths around the SHA3-256 (136) and SHAKE128 (168) rate boundaries.
  for (size_t len : {0U, 1U, 135U, 136U, 137U, 167U, 168U, 169U, 500U}) {
    const auto msg = pattern(len);
    const auto expected = pq::hash::sha3_256(msg);
    for (size_t chunk : {1U, 7U, 64U, 136U}) {
      pq::hash::Sha3_256 h;
      for (size_t off = 0; off < len; off += chunk) {
        h.update(pq::ByteView(msg).subspan(off, std::min(chunk, len - off)));
      }
      std::array<uint8_t, 32> got{};
      h.finalize(got);
      EXPECT_EQ(got, expected) << "len=" << len << " chunk=" << chunk;
    }
  }
}

TEST(Sponge, ChunkedSqueezeMatchesOneShot) {
  const auto msg = pattern(50);
  std::vector<uint8_t> expected(1000);
  pq::hash::shake128(expected, msg);
  for (size_t chunk : {1U, 3U, 167U, 168U, 169U, 500U}) {
    pq::hash::Shake128 x;
    x.absorb(msg);
    std::vector<uint8_t> got(expected.size());
    for (size_t off = 0; off < got.size(); off += chunk) {
      x.squeeze(pq::MutByteView(got).subspan(off, std::min(chunk, got.size() - off)));
    }
    EXPECT_EQ(got, expected) << "chunk=" << chunk;
  }
}

TEST(Sponge, AbsorbAfterSqueezeThrows) {
  pq::hash::Shake256 x;
  std::array<uint8_t, 4> out{};
  x.squeeze(out);
  EXPECT_THROW(x.absorb(out), pq::Error);
  x.reset();
  EXPECT_NO_THROW(x.absorb(out));
}

TEST(Sponge, InvalidRateThrows) {
  EXPECT_THROW(pq::hash::KeccakSponge(0, pq::hash::kSha3Suffix), pq::Error);
  EXPECT_THROW(pq::hash::KeccakSponge(200, pq::hash::kSha3Suffix), pq::Error);
  EXPECT_THROW(pq::hash::KeccakSponge(137, pq::hash::kSha3Suffix), pq::Error);
}

}  // namespace
