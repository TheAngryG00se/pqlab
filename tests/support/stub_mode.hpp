#pragma once

// Test double for an unauthenticated mode until src/mode exists (AGENTS.md, section 3).
// StubEcb honours the CipherMode contract for ECB: no IV, no padding, the length must be
// a multiple of the block size. Combined with XorCipher it is not encryption at all.

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "pq/cipher.hpp"
#include "pq/cipher_mode.hpp"
#include "pq/error.hpp"

namespace pq::test {

class StubEcb final : public CipherMode {
 public:
  explicit StubEcb(std::unique_ptr<BlockCipher> cipher)
      : cipher_(std::move(cipher)), name_(std::string(cipher_->name()) + "-ECB") {}

  [[nodiscard]] std::string_view name() const override { return name_; }
  [[nodiscard]] size_t key_size() const override { return cipher_->key_size(); }
  [[nodiscard]] size_t block_size() const override { return cipher_->block_size(); }
  [[nodiscard]] size_t iv_size() const override { return 0; }

  [[nodiscard]] Bytes encrypt(ByteView key, ByteView iv, ByteView pt) override {
    check(key, iv, pt);
    Bytes out(pt.size());
    for (size_t off = 0; off < pt.size(); off += block_size()) {
      cipher_->encrypt_block(pt.data() + off, out.data() + off);
    }
    return out;
  }

  [[nodiscard]] std::optional<SecureBytes> decrypt(ByteView key, ByteView iv,
                                                   ByteView ct) override {
    check(key, iv, ct);
    SecureBytes out(ct.size());
    for (size_t off = 0; off < ct.size(); off += block_size()) {
      cipher_->decrypt_block(ct.data() + off, out.data() + off);
    }
    return out;
  }

 private:
  void check(ByteView key, ByteView iv, ByteView data) {
    if (key.size() != key_size() || !iv.empty() || data.size() % block_size() != 0) {
      throw Error("StubEcb: wrong key, IV or data length");
    }
    cipher_->set_key(key);
  }

  std::unique_ptr<BlockCipher> cipher_;
  std::string name_;
};

}  // namespace pq::test
