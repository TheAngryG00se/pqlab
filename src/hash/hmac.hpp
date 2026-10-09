#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "hash/sha3.hpp"
#include "pq/secure_bytes.hpp"

namespace pq::hash {

// RFC 2104 (FIPS 198-1) HMAC over SHA3-256. The block size B is the SHA3-256
// rate, 136 bytes.
class HmacSha3_256 {
 public:
  static constexpr size_t kMacSize = Sha3_256::kDigestSize;
  static constexpr size_t kBlockSize = Sha3_256::kRate;

  explicit HmacSha3_256(ByteView key);

  void update(ByteView in) { inner_.update(in); }
  // Single use; call reset() to start a new message under the same key.
  void finalize(std::span<uint8_t, kMacSize> out);
  // Restores the state right after keying (inner and outer pads absorbed).
  void reset();

  // One-shot MAC of msg under the same key; does not touch the streaming state.
  void compute(std::span<uint8_t, kMacSize> out, ByteView msg) const;

 private:
  Sha3_256 inner_keyed_;
  Sha3_256 outer_keyed_;
  Sha3_256 inner_;
};

void hmac_sha3_256(std::span<uint8_t, 32> out, ByteView key, ByteView msg);

}  // namespace pq::hash
