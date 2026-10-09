#pragma once

#include <cstddef>
#include <cstdint>

#include "hash/keccak.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::hash {

// FIPS 202, Section 6.2: SHAKE128 / SHAKE256 with streaming output.
template <size_t SecurityBits>
class Shake {
 public:
  static constexpr size_t kRate = kKeccakStateBytes - 2 * (SecurityBits / 8);

  Shake() : sponge_(kRate, kShakeSuffix) {}

  // Throws pq::Error after the first squeeze().
  void absorb(ByteView in) { sponge_.absorb(in); }
  // Successive calls continue the same output stream.
  void squeeze(MutByteView out) { sponge_.squeeze(out); }
  void reset() noexcept { sponge_.reset(); }

 private:
  KeccakSponge sponge_;
};

using Shake128 = Shake<128>;
using Shake256 = Shake<256>;

void shake128(MutByteView out, ByteView in);
void shake256(MutByteView out, ByteView in);

}  // namespace pq::hash
