#pragma once

#include <memory>
#include <string>
#include <utility>

#include "pq/cipher.hpp"
#include "pq/cipher_mode.hpp"
#include "pq/error.hpp"

namespace pq::mode::detail {

class ModeBase : public CipherMode {
 public:
  [[nodiscard]] std::string_view name() const override { return name_; }
  [[nodiscard]] size_t key_size() const override { return cipher_->key_size(); }
  [[nodiscard]] size_t block_size() const override { return cipher_->block_size(); }
  [[nodiscard]] size_t iv_size() const override { return iv_size_; }

 protected:
  ModeBase(std::unique_ptr<BlockCipher> cipher, const char* mode, bool uses_iv)
      : cipher_(std::move(cipher)) {
    if (!cipher_ || cipher_->block_size() == 0) {
      throw Error("CipherMode: a nonempty block cipher is required");
    }
    name_ = std::string(cipher_->name()) + "-" + mode;
    iv_size_ = uses_iv ? cipher_->block_size() : 0;
  }

  void check_inputs(ByteView key, ByteView iv) const {
    if (key.size() != key_size() || iv.size() != iv_size()) {
      throw Error("CipherMode: wrong key or IV length");
    }
  }

  std::unique_ptr<BlockCipher> cipher_;

 private:
  std::string name_;
  size_t iv_size_;
};

}  // namespace pq::mode::detail
