#include "hash/hmac.hpp"

#include <algorithm>

namespace pq::hash {

// RFC 2104, Section 2.
HmacSha3_256::HmacSha3_256(ByteView key) {
  std::array<uint8_t, kBlockSize> k0{};
  if (key.size() > kBlockSize) {
    sha3_256(std::span<uint8_t, 32>(k0.data(), 32), key);
  } else {
    std::copy(key.begin(), key.end(), k0.begin());
  }

  std::array<uint8_t, kBlockSize> pad{};
  for (size_t i = 0; i < kBlockSize; ++i) {
    pad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
  }
  inner_keyed_.update(pad);
  for (size_t i = 0; i < kBlockSize; ++i) {
    pad[i] = static_cast<uint8_t>(k0[i] ^ 0x5C);
  }
  outer_keyed_.update(pad);
  inner_ = inner_keyed_;

  secure_zero(k0);
  secure_zero(pad);
}

void HmacSha3_256::finalize(std::span<uint8_t, kMacSize> out) {
  std::array<uint8_t, kMacSize> inner_digest{};
  inner_.finalize(inner_digest);
  Sha3_256 outer = outer_keyed_;
  outer.update(inner_digest);
  outer.finalize(out);
  secure_zero(inner_digest);
}

void HmacSha3_256::reset() { inner_ = inner_keyed_; }

void HmacSha3_256::compute(std::span<uint8_t, kMacSize> out, ByteView msg) const {
  std::array<uint8_t, kMacSize> inner_digest{};
  Sha3_256 inner = inner_keyed_;
  inner.update(msg);
  inner.finalize(inner_digest);
  Sha3_256 outer = outer_keyed_;
  outer.update(inner_digest);
  outer.finalize(out);
  secure_zero(inner_digest);
}

void hmac_sha3_256(std::span<uint8_t, 32> out, ByteView key, ByteView msg) {
  HmacSha3_256 mac(key);
  mac.update(msg);
  mac.finalize(out);
}

}  // namespace pq::hash
