#include "mode/padding.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace pq::mode::detail {
namespace {
void check_block_size(size_t block_size) {
  if (block_size == 0 || block_size > 255) {
    throw Error("PKCS#7: block size must be between 1 and 255 bytes");
  }
}
}  // namespace

// RFC 5652, Section 6.3: even a block-aligned message receives padding.
SecureBytes pkcs7_pad(ByteView plaintext, size_t block_size) {
  check_block_size(block_size);
  const size_t padding = block_size - plaintext.size() % block_size;
  if (plaintext.size() > std::numeric_limits<size_t>::max() - padding) {
    throw Error("PKCS#7: message too long");
  }
  SecureBytes result(plaintext.size() + padding);
  std::copy(plaintext.begin(), plaintext.end(), result.begin());
  std::fill(result.begin() + plaintext.size(), result.end(), static_cast<uint8_t>(padding));
  return result;
}

// RFC 5652, Section 6.3. Inspect the whole last block before releasing validity.
std::optional<size_t> pkcs7_unpadded_size(ByteView padded, size_t block_size) {
  check_block_size(block_size);
  if (padded.empty() || padded.size() % block_size != 0) {
    throw Error("PKCS#7: padded length must be a positive multiple of the block size");
  }
  const uint32_t padding = ct_value_barrier(static_cast<uint32_t>(padded.back()));
  uint32_t invalid = ct_is_zero_mask(padding);
  invalid |= (static_cast<uint32_t>(block_size) - padding) >> 31;
  for (uint32_t i = 0; i < block_size; ++i) {
    const uint32_t selected = 0U - ((i - padding) >> 31);
    invalid |= selected & (static_cast<uint32_t>(padded[padded.size() - 1 - i]) ^ padding);
  }
  // Validity and the accepted plaintext length are the public API result.
  if (ct_is_zero_mask(invalid) == 0) {
    return std::nullopt;
  }
  return padded.size() - padding;
}
}  // namespace pq::mode::detail
