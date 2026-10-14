#pragma once

#include <cstddef>
#include <optional>

#include "pq/secure_bytes.hpp"

namespace pq::mode::detail {

// RFC 5652, Section 6.3. Length is public; bytes of the final block are secret.
[[nodiscard]] SecureBytes pkcs7_pad(ByteView plaintext, size_t block_size);
[[nodiscard]] std::optional<size_t> pkcs7_unpadded_size(ByteView padded, size_t block_size);

}  // namespace pq::mode::detail
