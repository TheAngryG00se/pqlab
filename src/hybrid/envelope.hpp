#pragma once

// Wire format of the PQL1 envelope (AGENTS.md, section 10). All integers are
// big-endian.
//
//   part A (never changes):       "PQL1" | version[1] | aead_id[1] | data_nonce_prefix[7]
//   part B (changes on rewrap):   kem_id[1] | key_id[16] | len(ct_kem)[4] | ct_kem |
//                                 wrap_nonce[12] | wrapped_dek[32] | wrap_tag[16]
//   data   (never changes):       chunk_0 | tag_0 | chunk_1 | tag_1 | ...
//
// Only structure is checked here. Authenticity comes from the AEAD tags.

#include <array>
#include <cstddef>
#include <cstdint>

#include "pq/secure_bytes.hpp"

namespace pq::hybrid {

inline constexpr uint8_t kEnvelopeVersion = 1;
inline constexpr size_t kChunkSize = 64 * 1024;
inline constexpr size_t kNoncePrefixSize = 7;
inline constexpr size_t kNonceSize = 12;
inline constexpr size_t kTagSize = 16;
inline constexpr size_t kDekSize = 32;
inline constexpr size_t kKeyIdSize = 16;
inline constexpr size_t kPartASize = 4 + 1 + 1 + kNoncePrefixSize;

struct PartA {
  uint8_t version = kEnvelopeVersion;
  uint8_t aead_id = 0;
  std::array<uint8_t, kNoncePrefixSize> nonce_prefix{};
};

struct PartB {
  uint8_t kem_id = 0;
  std::array<uint8_t, kKeyIdSize> key_id{};
  Bytes kem_ct;
  std::array<uint8_t, kNonceSize> wrap_nonce{};
  std::array<uint8_t, kDekSize> wrapped_dek{};
  std::array<uint8_t, kTagSize> wrap_tag{};
};

struct Header {
  PartA a;
  PartB b;
  size_t size = 0;  // bytes taken by part A and part B; the data starts here
};

[[nodiscard]] Bytes serialize_part_a(const PartA& a);
[[nodiscard]] Bytes serialize_part_b(const PartB& b);

// Associated data of the DEK wrapping: part A followed by every field of part B
// that precedes wrapped_dek (kem_id, key_id, len, ct_kem, wrap_nonce). wrapped_dek
// and wrap_tag cannot authenticate themselves.
[[nodiscard]] Bytes wrap_aad(const PartA& a, const PartB& b);

// Throws pq::Error on a bad magic, an unsupported version or a truncated header.
[[nodiscard]] Header parse_header(ByteView envelope);

// data_nonce_prefix[7] | chunk index[4] | last-chunk flag[1].
[[nodiscard]] std::array<uint8_t, kNonceSize> chunk_nonce(
    const std::array<uint8_t, kNoncePrefixSize>& prefix, uint32_t index, bool last);

// key_id = SHA3-256(pk)[0..16].
[[nodiscard]] std::array<uint8_t, kKeyIdSize> compute_key_id(ByteView pk);

}  // namespace pq::hybrid
