#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "pq/secure_bytes.hpp"

namespace pq::hash {

inline constexpr size_t kHkdfSha3_256MaxOutput = 255 * 32;

// RFC 5869, Section 2.2. An empty salt means HashLen zero bytes.
void hkdf_sha3_256_extract(std::span<uint8_t, 32> prk, ByteView salt, ByteView ikm);

// RFC 5869, Section 2.3. Throws pq::Error if okm.size() > 255 * HashLen.
void hkdf_sha3_256_expand(MutByteView okm, ByteView prk, ByteView info);

// Extract-then-expand.
void hkdf_sha3_256(MutByteView okm, ByteView ikm, ByteView salt, ByteView info);

}  // namespace pq::hash
