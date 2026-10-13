#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

#include "pq/secure_bytes.hpp"

namespace pq {

// Unauthenticated block cipher modes on top of any BlockCipher, NIST SP 800-38A:
//   ECB  no IV, no padding: the length must be a multiple of block_size();
//   CBC  IV of block_size() bytes, always PKCS#7 padding (RFC 5652, Section 6.3);
//   CTR  initial counter block of block_size() bytes, any length, no padding.
// For benchmarks and analysis only: nothing here detects tampering, so pqtool and
// KEM-DEM protect data with Aead.
class CipherMode {
 public:
  virtual ~CipherMode() = default;

  [[nodiscard]] virtual std::string_view name() const = 0;  // "AES-256-CBC"
  [[nodiscard]] virtual size_t key_size() const = 0;
  [[nodiscard]] virtual size_t block_size() const = 0;
  [[nodiscard]] virtual size_t iv_size() const = 0;  // 0 for ECB, block_size() for CBC and CTR

  // Throws pq::Error on a wrong key or IV length, or (ECB) a length that is not a
  // multiple of block_size().
  [[nodiscard]] virtual Bytes encrypt(ByteView key, ByteView iv, ByteView pt) = 0;
  // Throws pq::Error as encrypt does, and for a CBC ciphertext whose length is not a
  // positive multiple of block_size(). std::nullopt if the PKCS#7 padding is invalid
  // (CBC only); no plaintext is released then. The padding check runs in constant time.
  // The plaintext may be a secret, hence SecureBytes.
  [[nodiscard]] virtual std::optional<SecureBytes> decrypt(ByteView key, ByteView iv,
                                                           ByteView ct) = 0;
};

}  // namespace pq
