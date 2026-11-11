#pragma once

#include "pq/secure_bytes.hpp"

namespace pq::mode::detail {

// NIST SP 800-38D, Algorithm 1. All spans must contain exactly 16 bytes.
// Output may overlap either operand; the caller owns and wipes secret output.
void ghash_multiply(ByteView first, ByteView second, MutByteView output);

// Algorithms 2 and 4, step 5: padded AAD, padded ciphertext, bit lengths.
void ghash_auth(ByteView h, ByteView aad, ByteView ciphertext, MutByteView output);

}  // namespace pq::mode::detail
