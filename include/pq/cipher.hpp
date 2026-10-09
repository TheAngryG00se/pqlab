#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "pq/secure_bytes.hpp"

namespace pq {

class BlockCipher {
 public:
  virtual ~BlockCipher() = default;

  [[nodiscard]] virtual std::string_view name() const = 0;  // "AES-256", "Kuznyechik"
  [[nodiscard]] virtual size_t block_size() const = 0;      // bytes
  [[nodiscard]] virtual size_t key_size() const = 0;        // bytes

  // Throws pq::Error if key.size() != key_size(). The round keys are secrets
  // and must be wiped by the destructor.
  virtual void set_key(ByteView key) = 0;

  // in and out are block_size() bytes and may alias.
  virtual void encrypt_block(const uint8_t* in, uint8_t* out) const = 0;
  virtual void decrypt_block(const uint8_t* in, uint8_t* out) const = 0;

  [[nodiscard]] virtual int rounds() const = 0;
  // Reduced-round variants are for analysis/ only. pqtool and KEM-DEM always
  // use the full number of rounds.
  virtual void set_rounds(int r) = 0;
};

}  // namespace pq
