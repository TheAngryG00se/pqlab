#include "mode/ghash.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

#include "core/endian.hpp"
#include "pq/error.hpp"

namespace pq::mode::detail {
namespace {
template <typename T, size_t N>
struct WipedArray {
  std::array<T, N> value{};
  ~WipedArray() { secure_zero(value.data(), sizeof(value)); }
};
}  // namespace

// NIST SP 800-38D, Algorithm 1: bit-serial multiplication, no secret table access.
void ghash_multiply(ByteView first, ByteView second, MutByteView output) {
  if (first.size() != 16 || second.size() != 16 || output.size() != 16) {
    throw Error("GHASH: operands must contain 16 bytes");
  }
  WipedArray<uint64_t, 6> storage;
  auto& w = storage.value;
  w[0] = load64_be(first.data());
  w[1] = load64_be(first.data() + 8);
  w[2] = load64_be(second.data());
  w[3] = load64_be(second.data() + 8);
  for (uint32_t i = 0; i < 128; ++i) {
    const uint64_t mask = uint64_t{0} - (w[0] >> 63);
    w[4] ^= w[2] & mask;
    w[5] ^= w[3] & mask;
    const uint64_t reduction = uint64_t{0} - (w[3] & 1U);
    w[3] = (w[3] >> 1) | (w[2] << 63);
    w[2] = (w[2] >> 1) ^ (UINT64_C(0xe100000000000000) & reduction);
    w[0] = (w[0] << 1) | (w[1] >> 63);
    w[1] <<= 1;
  }
  store64_be(output.data(), w[4]);
  store64_be(output.data() + 8, w[5]);
}

// NIST SP 800-38D, Algorithm 2 and Algorithm 4, steps 4-5.
void ghash_auth(ByteView h, ByteView aad, ByteView ciphertext, MutByteView output) {
  if (h.size() != 16 || output.size() != 16) {
    throw Error("GHASH: key and output must contain 16 bytes");
  }
  constexpr auto kMaxBytes = std::numeric_limits<uint64_t>::max() / 8;
  if (aad.size() > kMaxBytes || ciphertext.size() > kMaxBytes) {
    throw Error("GHASH: bit length exceeds 64 bits");
  }
  WipedArray<uint8_t, 16> state;
  const auto absorb = [&](ByteView input) {
    size_t offset = 0;
    while (offset < input.size()) {
      const size_t take = std::min(size_t{16}, input.size() - offset);
      for (size_t i = 0; i < take; ++i) state.value[i] ^= input[offset + i];
      ghash_multiply(state.value, h, state.value);
      offset += take;
    }
  };
  absorb(aad);
  absorb(ciphertext);
  std::array<uint8_t, 16> lengths{};  // Public lengths only.
  store64_be(lengths.data(), static_cast<uint64_t>(aad.size()) * 8);
  store64_be(lengths.data() + 8, static_cast<uint64_t>(ciphertext.size()) * 8);
  for (size_t i = 0; i < 16; ++i) state.value[i] ^= lengths[i];
  ghash_multiply(state.value, h, output);
}

}  // namespace pq::mode::detail
