#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "pq/cipher.hpp"

namespace pq::cipher {

// Scalar GOST R 34.12-2015 cipher. The table S-box is the documented
// exception to the project's secret-independent memory-access rule.
class Kuznyechik final : public BlockCipher {
 public:
  Kuznyechik() = default;
  ~Kuznyechik() override;
  Kuznyechik(const Kuznyechik&) = delete;
  Kuznyechik& operator=(const Kuznyechik&) = delete;
  Kuznyechik(Kuznyechik&&) = delete;
  Kuznyechik& operator=(Kuznyechik&&) = delete;

  [[nodiscard]] std::string_view name() const override { return "Kuznyechik"; }
  [[nodiscard]] size_t block_size() const override { return 16; }
  [[nodiscard]] size_t key_size() const override { return 32; }
  void set_key(ByteView key) override;
  void encrypt_block(const uint8_t* in, uint8_t* out) const override;
  void decrypt_block(const uint8_t* in, uint8_t* out) const override;

  [[nodiscard]] int rounds() const override { return rounds_; }
  // 10 = nine LSX steps followed by X[K_10]. Analysis-only r in [1, 10]
  // keeps r-1 LSX steps and the final X[K_r]; decryption is its inverse.
  void set_rounds(int r) override;

 private:
  std::array<uint8_t, 160> round_keys_{};
  int32_t rounds_ = 10;
  bool keyed_ = false;
};

}  // namespace pq::cipher
