#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "hash/keccak.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::hash {

// FIPS 202, Section 6.1: SHA3-d with capacity c = 2d, rate r = 1600 - 2d.
template <size_t DigestBytes>
class Sha3 {
 public:
  static constexpr size_t kDigestSize = DigestBytes;
  static constexpr size_t kRate = kKeccakStateBytes - 2 * DigestBytes;

  Sha3() : sponge_(kRate, kSha3Suffix) {}

  void update(ByteView in) { sponge_.absorb(in); }

  // Single use: call reset() before hashing another message.
  void finalize(std::span<uint8_t, DigestBytes> out) { sponge_.squeeze(out); }

  void reset() noexcept { sponge_.reset(); }

 private:
  KeccakSponge sponge_;
};

using Sha3_256 = Sha3<32>;
using Sha3_512 = Sha3<64>;

void sha3_256(std::span<uint8_t, 32> out, ByteView in);
void sha3_512(std::span<uint8_t, 64> out, ByteView in);

[[nodiscard]] std::array<uint8_t, 32> sha3_256(ByteView in);
[[nodiscard]] std::array<uint8_t, 64> sha3_512(ByteView in);

}  // namespace pq::hash
