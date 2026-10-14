#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "pq/cipher.hpp"

namespace pq::cipher {

// Byte-oriented FIPS 197-upd1 AES. The S-box lookup is not cache-constant-time.
class Aes final : public BlockCipher {
 public:
  explicit Aes(uint32_t key_bits = 256);
  ~Aes() override;

  Aes(const Aes&) = delete;
  Aes& operator=(const Aes&) = delete;
  Aes(Aes&&) = delete;
  Aes& operator=(Aes&&) = delete;

  [[nodiscard]] std::string_view name() const override;
  [[nodiscard]] size_t block_size() const override { return 16; }
  [[nodiscard]] size_t key_size() const override { return key_bytes_; }
  void set_key(ByteView key) override;
  void encrypt_block(const uint8_t* in, uint8_t* out) const override;
  void decrypt_block(const uint8_t* in, uint8_t* out) const override;

  [[nodiscard]] int rounds() const override { return rounds_; }
  // Existing BlockCipher contract: only analysis/ may request reduced rounds.
  void set_rounds(int r) override;

 private:
  std::array<uint8_t, 240> round_keys_{};
  size_t key_bytes_;
  int32_t full_rounds_;
  int32_t rounds_;
  bool keyed_ = false;
};

}  // namespace pq::cipher
