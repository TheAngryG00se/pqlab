#pragma once

// INSECURE test doubles standing in for AES and GCM until src/cipher and
// src/mode exist (AGENTS.md, section 3). They honour the same contract as the
// real ones: 12-byte nonce, 16-byte tag, ciphertext || tag, and a failed tag
// check returns std::nullopt without releasing plaintext.
//
// XorCipher: E(x) = x xor key[0..16). Not a cipher.
// StubGcm:   CTR-like keystream from the block cipher, tag = HMAC-SHA3-256.

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "core/endian.hpp"
#include "hash/hmac.hpp"
#include "pq/aead.hpp"
#include "pq/cipher.hpp"
#include "pq/ct.hpp"
#include "pq/error.hpp"

namespace pq::test {

class XorCipher final : public BlockCipher {
 public:
  explicit XorCipher(std::string name = "AES-256", size_t key_size = 32)
      : name_(std::move(name)), key_size_(key_size) {}

  [[nodiscard]] std::string_view name() const override { return name_; }
  [[nodiscard]] size_t block_size() const override { return 16; }
  [[nodiscard]] size_t key_size() const override { return key_size_; }

  void set_key(ByteView key) override {
    if (key.size() != key_size_) {
      throw Error("XorCipher: wrong key length");
    }
    std::copy_n(key.begin(), 16, key_.begin());
  }

  void encrypt_block(const uint8_t* in, uint8_t* out) const override {
    for (size_t i = 0; i < 16; ++i) {
      out[i] = static_cast<uint8_t>(in[i] ^ key_[i]);
    }
  }
  void decrypt_block(const uint8_t* in, uint8_t* out) const override { encrypt_block(in, out); }

  [[nodiscard]] int rounds() const override { return 1; }
  void set_rounds(int) override {}

 private:
  std::string name_;
  size_t key_size_;
  std::array<uint8_t, 16> key_{};
};

class StubGcm final : public Aead {
 public:
  explicit StubGcm(std::unique_ptr<BlockCipher> cipher)
      : cipher_(std::move(cipher)), name_(std::string(cipher_->name()) + "-GCM") {}

  [[nodiscard]] std::string_view name() const override { return name_; }
  [[nodiscard]] size_t key_size() const override { return cipher_->key_size(); }
  [[nodiscard]] size_t nonce_size() const override { return 12; }
  [[nodiscard]] size_t tag_size() const override { return 16; }

  [[nodiscard]] Bytes seal(ByteView key, ByteView nonce, ByteView aad, ByteView pt) override {
    check(key, nonce);
    Bytes out(pt.size() + kTag);
    keystream_xor(nonce, pt, out.data());
    tag(key, nonce, aad, ByteView(out.data(), pt.size()), out.data() + pt.size());
    return out;
  }

  [[nodiscard]] std::optional<SecureBytes> open(ByteView key, ByteView nonce, ByteView aad,
                                                ByteView ct) override {
    check(key, nonce);
    if (ct.size() < kTag) {
      return std::nullopt;
    }
    const ByteView body = ct.first(ct.size() - kTag);
    std::array<uint8_t, kTag> expected{};
    tag(key, nonce, aad, body, expected.data());
    if (!ct_equal(expected, ct.last(kTag))) {
      return std::nullopt;
    }
    SecureBytes pt(body.size());
    keystream_xor(nonce, body, pt.data());
    return pt;
  }

 private:
  static constexpr size_t kTag = 16;

  void check(ByteView key, ByteView nonce) {
    if (key.size() != key_size() || nonce.size() != 12) {
      throw Error("StubGcm: wrong key or nonce length");
    }
    cipher_->set_key(key);
  }

  void keystream_xor(ByteView nonce, ByteView in, uint8_t* out) const {
    std::array<uint8_t, 16> ctr_block{};
    std::array<uint8_t, 16> ks{};
    std::copy(nonce.begin(), nonce.end(), ctr_block.begin());
    for (size_t off = 0, j = 1; off < in.size(); off += 16, ++j) {
      store32_be(ctr_block.data() + 12, static_cast<uint32_t>(j));
      cipher_->encrypt_block(ctr_block.data(), ks.data());
      const size_t n = std::min<size_t>(16, in.size() - off);
      for (size_t i = 0; i < n; ++i) {
        out[off + i] = static_cast<uint8_t>(in[off + i] ^ ks[i]);
      }
    }
  }

  static void tag(ByteView key, ByteView nonce, ByteView aad, ByteView body, uint8_t* out) {
    hash::HmacSha3_256 mac(key);
    std::array<uint8_t, 16> lens{};
    store64_be(lens.data(), aad.size());
    store64_be(lens.data() + 8, body.size());
    mac.update(nonce);
    mac.update(lens);
    mac.update(aad);
    mac.update(body);
    std::array<uint8_t, 32> full{};
    mac.finalize(full);
    std::copy_n(full.begin(), kTag, out);
  }

  std::unique_ptr<BlockCipher> cipher_;
  std::string name_;
};

}  // namespace pq::test
