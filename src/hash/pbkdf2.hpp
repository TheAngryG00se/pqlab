#pragma once

#include <cstdint>

#include "pq/secure_bytes.hpp"

namespace pq::hash {

// RFC 8018, Section 5.2 (PBKDF2) with PRF = HMAC-SHA3-256.
// Throws pq::Error if iterations == 0 or out is empty.
void pbkdf2_hmac_sha3_256(MutByteView out, ByteView password, ByteView salt, uint32_t iterations);

}  // namespace pq::hash
