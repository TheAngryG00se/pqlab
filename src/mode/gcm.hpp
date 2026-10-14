#pragma once

#include <memory>
#include <string>

#include "pq/aead.hpp"
#include "pq/cipher.hpp"

namespace pq::mode {

// SP 800-38D with 96-bit nonces and 128-bit tags, the fixed PQL1 profile.
// Nonce uniqueness for a given key is the caller's responsibility.
class Gcm final : public Aead {
 public:
  explicit Gcm(std::unique_ptr<BlockCipher> cipher);
  [[nodiscard]] std::string_view name() const override { return name_; }
  [[nodiscard]] size_t key_size() const override { return cipher_->key_size(); }
  [[nodiscard]] size_t nonce_size() const override { return 12; }
  [[nodiscard]] size_t tag_size() const override { return 16; }
  [[nodiscard]] Bytes seal(ByteView key, ByteView nonce, ByteView aad, ByteView pt) override;
  [[nodiscard]] std::optional<SecureBytes> open(ByteView key, ByteView nonce, ByteView aad,
                                                ByteView ct) override;

 private:
  void check_inputs(ByteView key, ByteView nonce, size_t aad_size, size_t message_size) const;
  void transform(ByteView nonce, ByteView input, MutByteView output);
  void authenticate(ByteView nonce, ByteView aad, ByteView ciphertext, MutByteView tag);

  std::unique_ptr<BlockCipher> cipher_;
  std::string name_;
};

namespace detail {
// Public-length validation, separated to test the boundary without huge allocations.
void check_gcm_lengths(uint64_t aad_bytes, uint64_t message_bytes);
}  // namespace detail

}  // namespace pq::mode
