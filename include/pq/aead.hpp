#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

#include "pq/secure_bytes.hpp"

namespace pq {

// Authenticated encryption on top of any BlockCipher (GCM).
// Ciphertext layout: encrypted data || tag.
class Aead {
 public:
  virtual ~Aead() = default;

  [[nodiscard]] virtual std::string_view name() const = 0;  // "AES-256-GCM"
  [[nodiscard]] virtual size_t key_size() const = 0;
  [[nodiscard]] virtual size_t nonce_size() const = 0;
  [[nodiscard]] virtual size_t tag_size() const = 0;

  // Throw pq::Error on wrong key or nonce length.
  [[nodiscard]] virtual Bytes seal(ByteView key, ByteView nonce, ByteView aad, ByteView pt) = 0;
  // std::nullopt if the tag does not verify; no plaintext is released then.
  // The plaintext may be a secret (wrapped DEK, keystore seed), hence SecureBytes.
  [[nodiscard]] virtual std::optional<SecureBytes> open(ByteView key, ByteView nonce, ByteView aad,
                                                        ByteView ct) = 0;
};

}  // namespace pq
